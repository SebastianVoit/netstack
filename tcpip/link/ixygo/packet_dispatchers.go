// Copyright 2021 Sebastian Voit.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

func (d *rxBatchDispatcher) allocateViews(bufConfig []int) {
	for k := 0; k < len(d.views); k++ {
		// implement GSO here should we support it in the future.
		for i := 0; i < len(bufConfig); i++ {
			if d.views[k][i] != nil {
				break
			}
			d.views[k][i] = buffer.NewView(bufConfig[i])
		}
	}
}

// rxBatchDispatcher reads up to BatchSize packets at a time from the
// ixy device and dispatches it.
func (d *rxBatchDispatcher) dispatch() (bool, *tcpip.Error) {
	d.allocateViews(BufConfig)

	// read packets and put them into the views
	nMsgs, err := d.ixyBlockingRead(d.rxQueue, d.pktBufs)
	if err != nil {
		// drop packets on error but handle nothing else
		for i := 0; i < nMsgs; i++ {
			driver.PktBufFree(d.pktBufs[i])
		}
		return false, err
	}

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

		// Prepare e.views for another packet: release used views.
		for i := 0; i < used; i++ {
			d.views[k][i] = nil
		}
		// Free the pktBuf
		driver.PktBufFree(d.pktBufs[k])
	}

	return true, nil
}

// reads from an rx queue of the ixy device of the associated endpoint
// and copies these contents into views
// blocks until packets are read
// use this with a reasonable bufs size, e.g. 1<<5 or larger (1<<8 performs best for the driver)
func (d *rxBatchDispatcher) ixyBlockingRead(queueID uint16, bufs []*driver.PktBuf) (int, *tcpip.Error) {
	read := 0
	// fetch a batch of packets
	for read == 0 {
		rec, err := d.e.dev.RxBatch(queueID, bufs)
		read += int(rec)
		if err != nil {
			return read, tcpip.ErrClosedQueue
		}
	}
	// copy the data into the views
	for k := 0; k < read; k++ {
		c := 0
		for i := 0; ; i++ {
			nCpy := copy(d.views[k][i], bufs[k].Pkt[c:bufs[k].Size])
			if nCpy <= len(d.views[k][i]) {
				break
			}
			c += nCpy
		}
	}
	return read, nil
}
