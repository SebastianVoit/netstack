package ixygo

import (
	"github.com/SebastianVoit/netstack/driver"
	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/buffer"
	"github.com/SebastianVoit/netstack/tcpip/header"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

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

func (d *rxBatchDispatcher) freePktBufs(rec int) {
	// free all PktBufs and delete all references (slices) to them
	for i := 0; i < rec; i++ {
		driver.PktBufFree(d.pktBufs[i])
		d.pktBufs[i] = nil
	}
	for i := 0; i < len(d.views); i++ {
		for j := 0; j < len(d.views[i]); j++ {
			d.views[i][j] = nil
		}
	}
}

// initViews builds a buffer.View structure ontop of the currently allocate PktBufs
// ignores all pktBufs that are not filled
func (d *rxBatchDispatcher) initViews(bufConfig []int) {
	for k := 0; k < len(d.views) && d.pktBufs[k] != nil; k++ {
		// implement GSO here should we support it in the future.
		at := 0
		for i := 0; i < len(bufConfig); i++ {
			if d.views[k][i] != nil {
				break
			}
			overfull := at + BufConfig[i] - int(d.pktBufs[k].Size)
			var b buffer.View
			if overfull > 0 {
				// -> all following views will be [] and later capped
				b = buffer.View(d.pktBufs[k].Pkt[at:d.pktBufs[k].Size])
			} else {
				b = buffer.View(d.pktBufs[k].Pkt[at : at+BufConfig[i]])
			}
			at += len(b)
			d.views[k][i] = b
		}
	}
}

// rxBatchDispatcher reads up to BatchSize packets at a time from the
// ixy device and dispatches it.
func (d *rxBatchDispatcher) dispatch() (bool, *tcpip.Error) {
	// read packets and put them into the views
	nMsgs, err := d.ixyBlockingRead(d.rxQueue, d.pktBufs)
	defer d.freePktBufs(nMsgs)
	if err != nil {
		return false, err
	}
	// PktBufs and views are cleaned when all the packets are processed (or this function unexpectedly stops)
	d.initViews(BufConfig)
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
				return true, nil
			}
		}

		used := d.capViews(k, n, BufConfig)
		vv := buffer.NewVectorisedView(int(n), d.views[k][:used])
		vv.TrimFront(d.e.hdrSize)
		d.e.dispatcher.DeliverNetworkPacket(d.e, remote, local, p, vv)
	}

	return true, nil
}

// reads from an rx queue of the ixy device of the associated endpoint
// blocks until packets are read
// use this with a reasonable bufs size, e.g. 1<<5 or larger (1<<8 performs best)
func (d *rxBatchDispatcher) ixyBlockingRead(queueID uint16, bufs []*driver.PktBuf) (int, *tcpip.Error) {
	read := 0
	for read == 0 {
		rec, err := d.e.dev.RxBatch(queueID, bufs)
		read += int(rec)
		if err != nil {
			return read, tcpip.ErrClosedQueue
		}
	}
	return read, nil
}
