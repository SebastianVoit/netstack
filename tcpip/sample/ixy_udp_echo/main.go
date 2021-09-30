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
// device, and listens on a port. Data received by the server in the accepted
// connections is echoed back to the clients.
//
// ixy.go is implemented for Intel ixgbe 82599 NICs. Use lspci to find out its
// pci address and enable huge pages via the script in /driver.
// All disclaimers for ixy.go apply here as well.

// Connect via telnet or nc.

package main

import (
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
	"github.com/SebastianVoit/netstack/tcpip/link/ixygo"
	"github.com/SebastianVoit/netstack/tcpip/link/sniffer"
	"github.com/SebastianVoit/netstack/tcpip/network/arp"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv4"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv6"
	"github.com/SebastianVoit/netstack/tcpip/stack"
	"github.com/SebastianVoit/netstack/tcpip/transport/tcp"
	"github.com/SebastianVoit/netstack/tcpip/transport/udp"
	"github.com/SebastianVoit/netstack/waiter"
)

var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in ixy device")
var sniff = flag.Bool("s", false, "enables packet sniffing to log those to stdout")
var verbose = flag.Bool("v", false, "the verbose flag enables additional feedback during program operation")
var numRx = flag.Uint64("numRx", 1, "number of RX queues")
var numTx = flag.Uint64("numTx", 1, "number of TX queues")

func main() {
	flag.Parse()
	if len(flag.Args()) != 3 {
		log.Fatal("Usage: ", os.Args[0], " <pci-address> <local-address> <local-port>")
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

	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Parse the IP address. Support both ipv4 and ipv6.
	parsedAddr := net.ParseIP(addrName)
	if parsedAddr == nil {
		log.Fatalf("Bad IP address: %v", addrName)
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
		log.Fatalf("Unknown IP type: %v", addrName)
	}

	localPort, err := strconv.Atoi(portName)
	if err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	}

	// Create the stack with IP and TCP protocols, then add an ixy-based
	// NIC and address.
	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}, []string{tcp.ProtocolName}, stack.Options{})

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
		GSOMaxSize:     0, // ignored, always set to zero as ixy.go doesn't support GSO
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

	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}

	if *verbose {
		fmt.Println("Set up ixy-based NIC and added ARP and IP capabilities.")
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

	// Create UDP endpoint, bind it, then echo incoming packets.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(e)
	}

	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{NIC: 0, Addr: "", Port: uint16(localPort)}); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	if *verbose {
		fmt.Println("Created and bound UDP endpoint, ready to echo packets.")
	}

	// Wait for packets to appear.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	if *verbose {
		fmt.Println("Ready to answer requests.")
	}

	for {
		var addr tcpip.FullAddress
		v, _, err := ep.Read(&addr)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}
			log.Fatal("Read error: ", err)
		}
		if *verbose {
			fmt.Println("Received request, sending UDP reply.")
		}
		ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{To: &addr})
	}
}
