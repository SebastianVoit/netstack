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

// +build linux

// This sample creates a stack with TCP and IPv4 protocols on top of an ixy
// device, and connects to a peer. Similar to "nc <address> <port>". While the
// sample is running, attempts to connect to its IPv4 address will result in
// a RST segment.
//
// ixy.go is implemented for Intel ixgbe 82599 NICs. Use lspci to find out its
// pci address and enable huge pages via the script in /driver.
// All disclaimers for ixy.go apply here as well.
//
// This will attempt to connect to the linux host's stack. One can run nc in
// listen mode to accept a connect from ixy_tcp_connect and exchange data.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SebastianVoit/netstack/driver"
	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/buffer"
	"github.com/SebastianVoit/netstack/tcpip/link/ixygo"
	"github.com/SebastianVoit/netstack/tcpip/link/sniffer"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv4"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv6"
	"github.com/SebastianVoit/netstack/tcpip/stack"
	"github.com/SebastianVoit/netstack/tcpip/transport/tcp"
	"github.com/SebastianVoit/netstack/waiter"
)

var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in ixy device")
var sniff = flag.Bool("s", false, "enables packet sniffing to log those to stdout")
var verbose = flag.Bool("v", false, "the verbose flag enables additional feedback during program operation")
var numRx = flag.Uint64("numRx", 1, "number of RX queues")
var numTx = flag.Uint64("numTx", 1, "number of TX queues")

// writer reads from standard input and writes to the endpoint until standard
// input is closed. It signals that it's done by closing the provided channel.
func writer(ch chan struct{}, ep tcpip.Endpoint) {
	defer func() {
		ep.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()

	if *verbose {
		fmt.Println("Created writer, please start typing.")
	}

	r := bufio.NewReader(os.Stdin)
	for {
		v := buffer.NewView(1024)
		n, err := r.Read(v)
		if err != nil {
			return
		}

		v.CapLength(n)
		for len(v) > 0 {
			n, _, err := ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
			if err != nil {
				fmt.Println("Write failed:", err)
				return
			}

			v.TrimFront(int(n))
		}
	}
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 5 {
		log.Fatal("Usage: ", os.Args[0], " <pci-address> <local-ipv4-address> <local-port> <remote-ipv4-address> <remote-port>")
	}

	queueErrStr := ""
	if *numRx < 1 {
		queueErrStr += "\n\tnumRx must be > 0"
	}
	if *numRx > 0xffff {
		queueErrStr += "\n\tnumRx must be a Uint16"
	}
	if *numTx < 1 {
		queueErrStr += "\n\tnumTx must be > 0"
	}
	if *numRx > 0xffff {
		queueErrStr += "\n\tnumTx must be a Uint16"
	}
	if queueErrStr != "" {
		log.Fatal("Errors in specifying the RX and TX queue arguments:" + queueErrStr)
	}
	numRx16 := uint16(*numRx)
	numTx16 := uint16(*numTx)
	pciAddr := flag.Arg(0)
	addrName := flag.Arg(1)
	portName := flag.Arg(2)
	remoteAddrName := flag.Arg(3)
	remotePortName := flag.Arg(4)

	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Parse the IP address. Support both ipv4 and ipv6.
	parsedAddr := net.ParseIP(addrName)
	if parsedAddr == nil {
		log.Fatalf("Bad local IP address: %v", addrName)
	}
	parsedRemoteAddr := net.ParseIP(remoteAddrName)
	if parsedRemoteAddr == nil {
		log.Fatalf("Bad remote IP address: %v", remoteAddrName)
	}

	var addr tcpip.Address
	var proto tcpip.NetworkProtocolNumber
	if parsedAddr.To4() != nil {
		addr = tcpip.Address(parsedAddr.To4())
		proto = ipv4.ProtocolNumber
	} else if parsedAddr.To16() != nil {
		addr = tcpip.Address(parsedAddr.To16())
		proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown local IP type: %v", addrName)
	}

	remote := tcpip.FullAddress{
		NIC: 1,
	}

	if parsedRemoteAddr.To4() != nil {
		if proto != ipv4.ProtocolNumber {
			log.Fatalf("Mismatching IP versions: src is %v, dst is %v", proto, ipv4.ProtocolNumber)
		}
		remote.Addr = tcpip.Address(parsedRemoteAddr.To4())
	} else if parsedAddr.To16() != nil {
		if proto != ipv6.ProtocolNumber {
			log.Fatalf("Mismatching IP versions: src is %v, dst is %v", proto, ipv6.ProtocolNumber)
		}
		remote.Addr = tcpip.Address(parsedRemoteAddr.To16())
	} else {
		log.Fatalf("Unknown remote IP type: %v", addrName)
	}

	var localPort uint16
	if v, err := strconv.Atoi(portName); err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	} else {
		localPort = uint16(v)
	}

	if v, err := strconv.Atoi(remotePortName); err != nil {
		log.Fatalf("Unable to convert port %v: %v", remotePortName, err)
	} else {
		remote.Port = uint16(v)
	}

	// Create the stack with IP and TCP protocols, then add an ixy-based
	// NIC and address.
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName /*, arp.ProtocolName*/}, []string{tcp.ProtocolName}, stack.Options{})

	mtu := uint32(1500) // TODO: get max mtu from NIC?

	// Initialize ixgbe device
	dev := driver.IxyInit(pciAddr, numRx16, numTx16)

	if *verbose {
		fmt.Printf("Initialized the ixy driver with PCI Address: %v, #RxQueues: %v, #TxQueues: %v\n", pciAddr, numRx16, numTx16)
	}

	linkID, err := ixygo.New(&ixygo.Options{
		Dev:            dev,
		TxEntries:      0, // uses default
		MTU:            mtu,
		EthernetHeader: true,
		Address:        tcpip.LinkAddress(maddr),
	})
	if err != nil {
		log.Fatal(err)
	}
	// TODO (optional): use sniffer to write packets to a file
	if *sniff {
		if err := s.CreateNIC(1, sniffer.New(linkID)); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := s.CreateNIC(1, linkID); err != nil {
			log.Fatal(err)
		}
	}

	if err := s.AddAddress(1, proto, addr); err != nil {
		log.Fatal(err)
	}

	/*if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}*/

	if *verbose {
		fmt.Println("Set up ixy-based NIC and added IP capabilities.")
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", len(addr))),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", len(addr))),
			Gateway:     "",
			NIC:         1,
		},
	})

	if *verbose {
		fmt.Println("Added default entry to the routing table.")
	}

	// Create TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(e)
	}

	if *verbose {
		fmt.Println("Created TCP enpoint.")
	}

	// Bind if a port is specified.
	if localPort != 0 {
		if err := ep.Bind(tcpip.FullAddress{NIC: 0, Addr: "", Port: localPort}); err != nil {
			log.Fatal("Bind failed: ", err)
		}
	}

	// Issue connect request and wait for it to complete.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	terr := ep.Connect(remote)
	if terr == tcpip.ErrConnectStarted {
		fmt.Println("Connect is pending...")
		<-notifyCh
		terr = ep.GetSockOpt(tcpip.ErrorOption{})
	}
	wq.EventUnregister(&waitEntry)

	if terr != nil {
		log.Fatal("Unable to connect: ", terr)
	}

	fmt.Println("Connected")

	// Start the writer in its own goroutine.
	writerCompletedCh := make(chan struct{})
	if *verbose {
		fmt.Println("Setup completed, starting writer and reader.")
	}
	go writer(writerCompletedCh, ep)

	// Read data and write to standard output until the peer closes the
	// connection from its side.
	wq.EventRegister(&waitEntry, waiter.EventIn)
	for {
		v, _, err := ep.Read(nil)
		if err != nil {
			if err == tcpip.ErrClosedForReceive {
				break
			}

			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}

			log.Fatal("Read() failed:", err)
		}

		os.Stdout.Write(v)
	}
	wq.EventUnregister(&waitEntry)

	// The reader has completed. Now wait for the writer as well.
	<-writerCompletedCh

	if *verbose {
		fmt.Println("Connection closed, shutting down.")
	}

	ep.Close()
}
