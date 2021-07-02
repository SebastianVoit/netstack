// Copyright 2018 The gVisor Authors.
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

// +build linux

package ixygo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/SebastianVoit/netstack/driver"
	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/buffer"
	"github.com/SebastianVoit/netstack/tcpip/header"
	"github.com/SebastianVoit/netstack/tcpip/stack"
)

const (
	mtu        = 1500
	laddr      = tcpip.LinkAddress("\x11\x22\x33\x44\x55\x66")
	raddr      = tcpip.LinkAddress("\x77\x88\x99\xaa\xbb\xcc")
	pci        = "" // use the correct pci address here, look up via lspci. Format: aaaa:bb:cc.d
	rxqs       = uint16(1)
	txqs       = uint16(1)
	proto      = 10
	csumOffset = 48
	//gsoMSS     = 500
)

const (
	timeout = time.Second * 5
)

type packetInfo struct {
	raddr    tcpip.LinkAddress
	proto    tcpip.NetworkProtocolNumber
	contents buffer.View
}

type context struct {
	t    *testing.T
	dev  driver.IxyInterface
	ep   stack.LinkEndpoint
	ch   chan packetInfo
	done chan struct{}
}

func newContext(t *testing.T, opt *Options) *context {
	done := make(chan struct{}, 1)
	opt.ClosedFunc = func(*tcpip.Error) {
		done <- struct{}{}
	}

	epID, err := New(opt)
	if err != nil {
		t.Fatalf("Failed to create ixy.go endpoint: %v", err)
	}
	ep := stack.FindLinkEndpoint(epID).(*endpoint)

	c := &context{
		t:    t,
		dev:  opt.Dev,
		ep:   ep,
		ch:   make(chan packetInfo, 100),
		done: done,
	}

	ep.Attach(c)

	return c
}

func (c *context) cleanup(d *driver.IxyDummy) {
	// close the dummy so the channel will be filled
	for i := uint16(0); i < c.dev.GetIxyDev().NumRxQueues; i++ {
		d.RxClosed[i] = true
	}
	<-c.done
	for i := uint16(0); i < c.dev.GetIxyDev().NumTxQueues; i++ {
		d.TxClosed[i] = true
	}
}

/*func initDriver() driver.IxyInterface {
	return driver.IxyInit(pci, rxqs, txqs)
}*/

// to call the closed func, we need an rx queue that can later return an error
func initDummy(rxBufs uint32, rxQueues, txQueues uint16) *driver.IxyDummy {
	// allocate BatchSize entries, we don't need more for testing
	if rxQueues < 1 {
		rxQueues = 1
	}
	var mp *driver.Mempool
	if rxBufs > 0 {
		mp = driver.MemoryAllocateMempool(rxBufs, 0)
	} else {
		mp = nil
	}
	dummy := &driver.IxyDummy{
		Ixy:      driver.IxyDevice{DriverName: "dummy", NumRxQueues: rxQueues, NumTxQueues: txQueues},
		PktData:  nil,
		RxMpool:  mp,
		RxClosed: make([]bool, rxQueues),
		TxClosed: make([]bool, txQueues),
		TxDone:   make(chan struct{}),
	}
	return dummy
}

func (c *context) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remote tcpip.LinkAddress, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	c.ch <- packetInfo{remote, protocol, vv.ToView()}
}

// be careful from here on: drivers cannot be cleaned up except by program termination
// due to this fact be careful from here on, especially when using muliple contexts in one test

func TestNoEthernetProperties(t *testing.T) {
	dummy := initDummy(0, 0, 0)
	c := newContext(t, &Options{MTU: mtu, Dev: dummy})
	defer c.cleanup(dummy)

	if want, v := uint16(0), c.ep.MaxHeaderLength(); want != v {
		t.Fatalf("MaxHeaderLength() = %v, want %v", v, want)
	}

	if want, v := uint32(mtu), c.ep.MTU(); want != v {
		t.Fatalf("MTU() = %v, want %v", v, want)
	}
}

func TestEthernetProperties(t *testing.T) {
	dummy := initDummy(0, 0, 0)
	c := newContext(t, &Options{EthernetHeader: true, MTU: mtu, Dev: dummy})
	defer c.cleanup(dummy)

	if want, v := uint16(header.EthernetMinimumSize), c.ep.MaxHeaderLength(); want != v {
		t.Fatalf("MaxHeaderLength() = %v, want %v", v, want)
	}

	if want, v := uint32(mtu), c.ep.MTU(); want != v {
		t.Fatalf("MTU() = %v, want %v", v, want)
	}
}

func TestAddress(t *testing.T) {
	addrs := []tcpip.LinkAddress{"", "abc", "def"}
	for _, a := range addrs {
		t.Run(fmt.Sprintf("Address: %q", a), func(t *testing.T) {
			dummy := initDummy(0, 0, 0)
			c := newContext(t, &Options{Address: a, MTU: mtu, Dev: dummy})
			defer c.cleanup(dummy)

			if want, v := a, c.ep.LinkAddress(); want != v {
				t.Fatalf("LinkAddress() = %v, want %v", v, want)
			}
		})
	}
}

// send a single packet
func testWritePacket(t *testing.T, plen int, eth bool, gsoMaxSize uint32) {
	// dummy needs to know nothing, we just compare if dummy.Rec == want
	dummy := initDummy(0, 0, 1)
	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth, Dev: dummy /*GSOMaxSize: gsoMaxSize*/})
	defer c.cleanup(dummy)

	r := &stack.Route{
		RemoteLinkAddress: raddr,
	}

	// Build header.
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()) + 100)
	b := hdr.Prepend(100)
	for i := range b {
		b[i] = uint8(rand.Intn(256))
	}

	// Build payload and write.
	payload := make(buffer.View, plen)
	for i := range payload {
		payload[i] = uint8(rand.Intn(256))
	}
	want := append(hdr.View(), payload...)
	// WritePacket never returns
	if err := c.ep.WritePacket(r, nil /*gso*/, hdr, payload.ToVectorisedView(), proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
	// timeout in case of blocking
	to := time.NewTimer(timeout)
	select {
	case <-dummy.TxDone:
		to.Stop()
	case <-to.C:
		log.Fatalf("Timeout when waiting for the driver to finish the TxBatch")
	}
	// Get Rec from dummy, then compare with what we wrote.
	b = make([]byte, mtu)
	if len(dummy.Rec) == 0 {
		t.Fatalf("No packet sent")
	}
	n := copy(b, dummy.Rec[0])
	b = b[:n]
	if eth {
		h := header.Ethernet(b)
		b = b[header.EthernetMinimumSize:]

		if a := h.SourceAddress(); a != laddr {
			t.Fatalf("SourceAddress() = %v, want %v", a, laddr)
		}

		if a := h.DestinationAddress(); a != raddr {
			t.Fatalf("DestinationAddress() = %v, want %v", a, raddr)
		}

		if et := h.Type(); et != proto {
			t.Fatalf("Type() = %v, want %v", et, proto)
		}
	}
	if len(b) != len(want) {
		t.Fatalf("Read returned %v bytes, want %v", len(b), len(want))
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("Read returned %x, want %x", b, want)
	}
}

func TestWritePacket(t *testing.T) {
	lengths := []int{0, 100, 1000}
	eths := []bool{true, false}
	gsos := []uint32{0 /*, 32768*/}

	for _, eth := range eths {
		for _, plen := range lengths {
			for _, gso := range gsos {
				t.Run(
					fmt.Sprintf("Eth=%v,PayloadLen=%v,GSOMaxSize=%v", eth, plen, gso),
					func(t *testing.T) {
						testWritePacket(t, plen, eth, gso)
					},
				)
			}
		}
	}
}

func testWriteBatch(t *testing.T, txqs uint16, eth bool, plen int) {
	dummy := initDummy(0, 0, txqs)
	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth, Dev: dummy})
	defer c.cleanup(dummy)

	r := &stack.Route{
		RemoteLinkAddress: raddr,
	}

	bb := make([][]byte, BatchSize)
	want := make([][]byte, BatchSize)
	writeErr := make(chan struct {
		*tcpip.Error
		uint32
	}, BatchSize)
	var wg sync.WaitGroup
	for i := uint32(0); i < BatchSize; i++ {
		wg.Add(1)
		go func(i uint32) {
			hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()) + 100)
			b := hdr.Prepend(100)
			for j := range b {
				b[j] = uint8(rand.Intn(256))
			}
			// use index as first 32 payload bits to check later
			binary.BigEndian.PutUint32(b[:4], i)
			// Build payload and write.
			payload := make(buffer.View, plen)
			for i := range payload {
				payload[i] = uint8(rand.Intn(256))
			}
			want[i] = append(hdr.View(), payload...)
			if err := c.ep.WritePacket(r, nil /*gso*/, hdr, payload.ToVectorisedView(), proto); err != nil {
				writeErr <- struct {
					*tcpip.Error
					uint32
				}{err, i}
			}
		}(i)
		/*
			// Build header.
			hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()) + 100)
			b := hdr.Prepend(100)
			for j := range b {
				b[j] = uint8(rand.Intn(256))
			}
			// Build payload and write.
			payload := make(buffer.View, plen)
			for i := range payload {
				payload[i] = uint8(rand.Intn(256))
			}
			want[i] = append(hdr.View(), payload...)
			if err := c.ep.WritePacket(r, nil / *gso* /, hdr, payload.ToVectorisedView(), proto); err != nil {
				t.Fatalf("WritePacket failed: %v", err)
			}
		*/
	}
	wg.Wait()
	// group errors and log.Fatal them
	errStr := "Error(s) occured during parallel PacketWrites. Listing errors:\n"
	noErr := true
	for i := len(writeErr); i > 0; i-- {
		noErr = false
		tmp := <-writeErr
		errStr += fmt.Sprintf("\tWritePacket failed in goroutine %v:\n%v\n", tmp.uint32, tmp.Error)
	}
	if !noErr {
		t.Fatal(errStr)
	}

	to := time.NewTimer(timeout)
	select {
	case <-dummy.TxDone:
		to.Stop()
	case <-to.C:
		log.Fatalf("Timeout when waiting for the driver to finish the TxBatch")
	}

	// Get Rec from dummy, then compare with what we wrote.
	if len(dummy.Rec) < BatchSize {
		t.Fatal("WriteBatch failed: received less then BatchSize packets")
	}
	for i := 0; i < len(dummy.Rec); i++ {
		bb[i] = make([]byte, mtu)
		n := copy(bb[i], dummy.Rec[i])
		bb[i] = bb[i][:n]
		if eth {
			h := header.Ethernet(bb[i])
			bb[i] = bb[i][header.EthernetMinimumSize:]

			if a := h.SourceAddress(); a != laddr {
				t.Fatalf("SourceAddress() = %v, want %v", a, laddr)
			}

			if a := h.DestinationAddress(); a != raddr {
				t.Fatalf("DestinationAddress() = %v, want %v", a, raddr)
			}

			if et := h.Type(); et != proto {
				t.Fatalf("Type() = %v, want %v", et, proto)
			}
		}
		if len(bb[i]) != len(want[i]) {
			t.Fatalf("Read returned %v bytes, want %v", len(bb[i]), len(want[i]))
		}
		pId := binary.BigEndian.Uint32(bb[i][:4])
		if !bytes.Equal(bb[i], want[pId]) {
			t.Fatalf("Read from packet with id %v returned %x, want %x.", pId, bb[i], want[i])
		}
	}
}

// Test whether filling the buffers works correctly (TX)
// TODO?: run with different batch fill percentages (e.g. does the normal reset work?)
func TestWriteBatch(t *testing.T) {
	txqs := []uint16{1 /*, 2, 4, 8, 16*/}
	eths := []bool{true, false}
	lengths := []int{0, 100, 1000}
	for _, numtxqs := range txqs {
		for _, eth := range eths {
			for _, plen := range lengths {
				t.Run(
					fmt.Sprintf("TxQueues=%v,Eth=%v,PayloadLen=%v", txqs, eth, plen),
					func(t *testing.T) {
						testWriteBatch(t, numtxqs, eth, plen)
					},
				)
			}
		}
	}
}

func TestPreserveSrcAddress(t *testing.T) {
	baddr := tcpip.LinkAddress("\xcc\xbb\xaa\x77\x88\x99")

	dummy := initDummy(0, 0, 1)
	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: true, Dev: dummy})
	defer c.cleanup(dummy)

	// Set LocalLinkAddress in route to the value of the bridged address.
	r := &stack.Route{
		RemoteLinkAddress: raddr,
		LocalLinkAddress:  baddr,
	}

	// WritePacket panics given a prependable with anything less than
	// the minimum size of the ethernet header.
	hdr := buffer.NewPrependable(header.EthernetMinimumSize)
	if err := c.ep.WritePacket(r, nil /* gso */, hdr, buffer.VectorisedView{}, proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from the ixy dummy, then compare with what we wrote.
	<-dummy.TxDone
	b := make([]byte, mtu)
	if len(dummy.Rec) == 0 {
		t.Fatalf("No packet sent")
	}
	n := copy(b, dummy.Rec[0])
	b = b[:n]
	h := header.Ethernet(b)

	if a := h.SourceAddress(); a != baddr {
		t.Fatalf("SourceAddress() = %v, want %v", a, baddr)
	}
}

// Test RxBatch
func TestDeliverPacket(t *testing.T) {
	lengths := []int{100, 1000}
	eths := []bool{true, false}

	for _, eth := range eths {
		for _, plen := range lengths {
			t.Run(fmt.Sprintf("Eth=%v,PayloadLen=%v", eth, plen), func(t *testing.T) {
				dummy := initDummy(512, 1, 0)
				c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth, Dev: dummy})
				defer c.cleanup(dummy)

				// Build packet.
				b := make([]byte, plen)
				all := b
				for i := range b {
					b[i] = uint8(rand.Intn(256))
				}

				if !eth {
					// So that it looks like an IPv4 packet.
					b[0] = 0x40
				} else {
					hdr := make(header.Ethernet, header.EthernetMinimumSize)
					hdr.Encode(&header.EthernetFields{
						SrcAddr: raddr,
						DstAddr: laddr,
						Type:    proto,
					})
					all = append(hdr, b...)
				}
				// "Write" the packet -> will be received the next time RxBatch is called
				dummy.PktData = [][]byte{all}

				// Receive packet through the endpoint.
				select {
				case pi := <-c.ch:
					want := packetInfo{
						raddr:    raddr,
						proto:    proto,
						contents: b,
					}
					if !eth {
						want.proto = header.IPv4ProtocolNumber
						want.raddr = ""
					}
					if !reflect.DeepEqual(want, pi) {
						t.Fatalf("Unexpected received packet: %+v, want %+v", pi, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("Timed out waiting for packet")
				}
			})
		}
	}
}

func TestBufConfigFirst(t *testing.T) {
	// The stack assumes that the TCP/IP header is enterily contained in the first view.
	// Therefore, the first view needs to be large enough to contain the maximum TCP/IP
	// header, which is 120 bytes (60 bytes for IP + 60 bytes for TCP).
	want := 120
	got := BufConfig[0]
	if got < want {
		t.Errorf("first view has an invalid size: got %d, want >= %d", got, want)
	}
}
