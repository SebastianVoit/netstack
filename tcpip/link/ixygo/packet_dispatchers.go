package ixygo

import (
	"github.com/SebastianVoit/netstack/driver"
	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/buffer"
	"github.com/SebastianVoit/netstack/tcpip/header"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

// BatchSize defines the size of the rxBatches for the ixy device. 256 performs best
var BatchSize = 256

// rxBatchDispatcher uses driver.RxBatch() to read inbound packets and dispatches them
type rxBatchDispatcher struct {
	// rxQueue is the receive queue that is used to receive packets.
	rxQueue uint16

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// views are the actual buffers that hold the packet contents.
	views [][]buffer.View

	// pktBufs will be filled with packets from the ixy driver.
	// Receiveing in small batches is slow
	// -> we receive once and dispatch packet by packet
	pktBufs []*driver.PktBuf

	// keeps track of how many packets are in our buffer
	//rec uint32

	// keeps track of how many packets from the buffer are done
	//done uint32
}

func newRxBatchDispatcher(rxQueue uint16, e *endpoint) (linkDispatcher, error) {
	d := &rxBatchDispatcher{rxQueue: rxQueue, e: e}
	d.views = make([][]buffer.View, BatchSize)
	for i := range d.views {
		d.views[i] = make([]buffer.View, len(BufConfig))
	}
	d.pktBufs = make([]*driver.PktBuf, BatchSize)
	return d, nil
}

func (d *rxBatchDispatcher) capViews(k, n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			d.views[k][i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func (d *rxBatchDispatcher) allocateViews(bufConfig []int) {
	for k := 0; k < len(d.views); k++ {
		// implement GSO here should we support it in the future.
		for i := 0; i < len(bufConfig); i++ {
			if d.views[k][i] != nil {
				break
			}
			b := buffer.NewView(bufConfig[i])
			d.views[k][i] = b
		}
	}
}

func (d *rxBatchDispatcher) freePktBufs() {
	for i := 0; i < BatchSize; i++ {
		driver.PktBufFree(d.pktBufs[i])
	}
}

// rxBatchDispatcher reads up to BatchSize packets at a time from the
// ixy device and dispatches it.
func (d *rxBatchDispatcher) dispatch() (bool, *tcpip.Error) {
	d.allocateViews(BufConfig)

	nMsgs, err := d.ixyBlockingRead(d.rxQueue, d.pktBufs)
	// free all PktBufs when leaving this function
	defer d.freePktBufs()
	if err != nil {
		return false, err
	}

	// Process each of received packets.
	for k := 0; k < nMsgs; k++ {
		n := int(d.pktBufs[k].Size)
		if n <= d.e.hdrSize {
			return false, nil
		}

		var (
			p             tcpip.NetworkProtocolNumber
			remote, local tcpip.LinkAddress
		)
		// tbh I really don't get how the packet is supposed to get into the views
		// get packet into the views and we're good I think?
		// for now assume it magically works and fix if it doesn't
		if d.e.hdrSize > 0 {
			eth := header.Ethernet(d.views[k][0])
			p = eth.Type()
			remote = eth.SourceAddress()
			local = eth.DestinationAddress()
		} else {
			// We don't get any indication of what the packet is, so try to guess
			// if it's an IPv4 or IPv6 packet.
			switch header.IPVersion(d.views[k][0]) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				// this makes the func ignore the rest of the packets but I doubt that this is relevant
				return true, nil
			}
		}

		used := d.capViews(k, n, BufConfig)
		vv := buffer.NewVectorisedView(int(n), d.views[k][:used])
		vv.TrimFront(d.e.hdrSize)
		d.e.dispatcher.DeliverNetworkPacket(d.e, remote, local, p, vv)

		// Prepare e.views for another packet: release used views.
		for i := 0; i < used; i++ {
			d.views[k][i] = nil
		}
	}

	return true, nil
}

// reads from an rx queue of the ixy device of the associated endpoint
// blocks until packets are read
// use this with a reasonable bufs size, e.g. 1<<5 or larger (1<<8 performs best)
func (d *rxBatchDispatcher) ixyBlockingRead(queueID uint16, bufs []*driver.PktBuf) (int, *tcpip.Error) {
	// TODO: lock the mempool? Prob not because we have exactly one dispatcher per queue
	read := 0
	for read == 0 {
		read = int(d.e.dev.RxBatch(queueID, bufs))
	}
	return read, nil
}
