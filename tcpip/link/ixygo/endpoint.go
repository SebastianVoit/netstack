// package ixygo contains untilities for using the netstack with the ixy.go
// userspace driver

// ixy.go based endpoints can be used in the networking stack by calling New()
// to create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().

package ixygo

import (
	"fmt"
	"sync"

	"github.com/SebastianVoit/netstack/driver"
	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/buffer"
	"github.com/SebastianVoit/netstack/tcpip/header"
	"github.com/SebastianVoit/netstack/tcpip/stack"
)

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	dispatch() (bool, *tcpip.Error)
}

/*
 * Things to note:
 * Multithreading/Goroutines: Mempools are not threadsafe! -> no Multithreading support for now
 * PacketBuffer: copy or can we make the stack allocate vv as PktBufs from the start? Prob an interface somewhere if we can ...
 * Also PacketBuffer: we need to free the PktBuf of received packets at some point. Also copy?
 */

type mxMempool struct {
	mu      sync.Mutex
	inUse   uint32
	mempool *(driver.Mempool)
}

// endpoint infos
type endpoint struct {
	// denotes the number of rx queues configured on the driver
	rxQueues uint16

	// denotes the number of tx queues configured on the driver
	txQueues uint16

	// pointer to the TX mempools with an aded lock, used for packet allocation etc.
	txMempools []*mxMempool

	// for now we just rotate through the queues for sending
	nxtTxQueue uint16

	// number of entries in the TX mempools
	txBufs uint32

	// the driver
	dev driver.IxyInterface

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// hdrSize specifies the link-layer header size. If set to 0, no header
	// is added/removed; otherwise an ethernet header is used.
	hdrSize int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	inboundDispatchers []linkDispatcher
	dispatcher         stack.NetworkDispatcher

	// packetDispatchMode controls the packet dispatcher used by this
	// endpoint.
	// Not sure if we need that at all
	//packetDispatchMode PacketDispatchMode

	// gsoMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	// GSO = generic segmentation offload. ixgbe has TSO but ixy.go doesn't implement it
	// -> ignore for now and maybe implement later
	//gsoMaxSize uint32
}

// Options to configure ixy device
type Options struct {
	// PCI Addrs of the NIC
	PciAddr string

	// Number of RX queues
	RxQueues uint16

	// Number of TX queues
	TxQueues uint16

	//Number of buffers per TC queue
	TxBufs uint32

	// Allow NIC stats?
	//Stats bool

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// ClosedFunc is a function to be called when an endpoint's peer (if
	// any) closes its end of the communication pipe.
	ClosedFunc func(*tcpip.Error)

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// GSOMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	// GSO = generic segmentation offload. ixgbe has TSO but ixy.go doesn't implement it
	// -> ignore for now and maybe implement later
	//GSOMaxSize uint32

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	// ixy.go uses this non-optionally -> ignored
	//TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	// ixy.go uses this non-optionally -> ignored
	//RXChecksumOffload bool
}

// New creates a new ixy.go based endpoint
// CreateNIC(id, LinkID) creates exactly one NIC with ixy as its LinkEndpoint (LinkID returned from New)
func New(opts *Options) (tcpip.LinkEndpointID, error) {
	// create new ixy device
	dev := driver.IxyInit(opts.PciAddr, opts.RxQueues, opts.TxQueues)

	/* stats should we need them:
	stats := driver.DeviceStats{}
	stats.StatsInit(dev)
	*/

	caps := stack.LinkEndpointCapabilities(0)
	caps |= stack.CapabilityRXChecksumOffload
	caps |= stack.CapabilityTXChecksumOffload

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	// finish configuring and then create a new endpoint struct

	e := &endpoint{
		rxQueues:   opts.RxQueues,
		txQueues:   opts.TxQueues,
		txBufs:     opts.TxBufs,
		txMempools: make([]*mxMempool, opts.TxQueues),
		dev:        dev,
		mtu:        opts.MTU,
		caps:       caps,
		closed:     opts.ClosedFunc,
		addr:       opts.Address,
		hdrSize:    hdrSize,
	}

	for i := uint16(0); i < e.rxQueues; i++ {
		inboundDispatcher, err := createInboundDispatcher(e, i)
		if err != nil {
			return 0, fmt.Errorf("createInboundDispatcher(...) = %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	for i := uint16(0); i < e.txQueues; i++ {
		e.txMempools[i].mempool = driver.MemoryAllocateMempool(e.txBufs, 0)
	}

	return stack.RegisterLinkEndpoint(e), nil
}

func createInboundDispatcher(e *endpoint, rxQueue uint16) (linkDispatcher, error) {
	// Use the ixy.go RxBatch dispatcher, we don't offer others
	inboundDispatcher, err := newRxBatchDispatcher(rxQueue, e)
	if err != nil {
		return nil, fmt.Errorf("newRxBatchDispatcher(%d, %+v) = %v", rxQueue, e, err)
	}
	return inboundDispatcher, nil
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
// mempools are fine as we only dispatch one goroutine per rxQueue (and thus per mempool)
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// Link endpoints are not savable. When transportation endpoints are
	// saved, they stop sending outgoing packets and all incoming packets
	// are rejected.
	for i := range e.inboundDispatchers {
		go e.dispatchLoop(e.inboundDispatchers[i])
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// WritePacket writes outbound packets to the ixgbe NIC. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize))
		ethHdr := &header.EthernetFields{
			DstAddr: r.RemoteLinkAddress,
			Type:    protocol,
		}

		// Preserve the src address if it's set in the route.
		if r.LocalLinkAddress != "" {
			ethHdr.SrcAddr = r.LocalLinkAddress
		} else {
			ethHdr.SrcAddr = e.addr
		}
		eth.Encode(ethHdr)
	}

	// implement GSO here should we support it in the future

	queueID := e.getQueueID(r, "")
	return e.ixySend(queueID, hdr.View(), payload.ToView(), nil)
}

// WriteRawPacket writes a raw packet directly to the file descriptor.
func (e *endpoint) WriteRawPacket(dest tcpip.Address, packet []byte) *tcpip.Error {
	return e.ixySend(e.getQueueID(nil, dest), packet, nil, nil)
}

// if a route is given, this method does not check for dest
func (e *endpoint) getQueueID(r *stack.Route, dest tcpip.Address) uint16 {
	// TODO: goroutines <-> queueID
	ret := e.nxtTxQueue
	e.nxtTxQueue++
	for e.nxtTxQueue >= e.txQueues {
		e.nxtTxQueue -= e.txQueues
	}
	return ret
}

func (e *endpoint) ixySend(queueID uint16, b1, b2, b3 []byte) *tcpip.Error {
	// Naive, would be better to group packets into a bigger []*(driver.PktBuf) but I don't think we can
	// buffer array for RxBatch
	bufs := make([]*(driver.PktBuf), 1)
	// lock mempool mutex (mempools are not thread safe)
	e.txMempools[queueID].mu.Lock()
	defer e.txMempools[queueID].mu.Unlock()
	// allocate a single packet
	pbuf := driver.PktBufAlloc(e.txMempools[queueID].mempool)
	if pbuf == nil {
		return tcpip.ErrNoBufferSpace
	}
	// copy the packet into the mempool
	at := copy(pbuf.Pkt, b1)
	if len(b2) != 0 {
		at += copy(pbuf.Pkt[at:], b2)
		if len(b3) != 0 {
			copy(pbuf.Pkt[at:], b3)
		}
	}
	// add packet to the sending slice
	bufs[0] = pbuf

	// enqueue packet(s)
	numTx := e.dev.TxBatch(queueID, bufs)
	// drop packets that couldn't fit
	if numTx < uint32(len(bufs)) {
		for i := numTx; i < uint32(len(bufs)); i++ {
			driver.PktBufFree(bufs[i])
		}
	}
	return nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) *tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}

// currently not supported
// GSOMaxSize returns the maximum GSO packet size.
/*func (e *endpoint) GSOMaxSize() uint32 {
	return e.gsoMaxSize
}*/

// InjectableEndpoint is an injectable ixy-based endpoint. The endpoint writes
// to the ixy device, but does not read from it. All reads come from injected packets.
type InjectableEndpoint struct {
	endpoint

	dispatcher stack.NetworkDispatcher
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// Inject injects an inbound packet.
func (e *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, protocol, vv)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(dev driver.IxyInterface, rxQueues, txQueues uint16, mtu uint32, capabilities stack.LinkEndpointCapabilities) (tcpip.LinkEndpointID, *InjectableEndpoint) {

	e := &InjectableEndpoint{endpoint: endpoint{
		dev:      dev,
		rxQueues: rxQueues,
		txQueues: txQueues,
		mtu:      mtu,
		caps:     capabilities,
	}}

	return stack.RegisterLinkEndpoint(e), e
}
