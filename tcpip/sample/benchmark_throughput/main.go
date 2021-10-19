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
	"encoding/binary"
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
	"github.com/SebastianVoit/netstack/tcpip/link/fdbased"
	"github.com/SebastianVoit/netstack/tcpip/link/ixygo"
	"github.com/SebastianVoit/netstack/tcpip/link/rawfile"
	"github.com/SebastianVoit/netstack/tcpip/link/sniffer"
	"github.com/SebastianVoit/netstack/tcpip/link/tun"
	"github.com/SebastianVoit/netstack/tcpip/network/arp"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv4"
	"github.com/SebastianVoit/netstack/tcpip/network/ipv6"
	"github.com/SebastianVoit/netstack/tcpip/stack"
	"github.com/SebastianVoit/netstack/tcpip/transport/tcp"
	"github.com/SebastianVoit/netstack/tcpip/transport/udp"
	"github.com/SebastianVoit/netstack/waiter"
)

var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in ixy device")
var verbose = flag.Bool("v", false, "the verbose flag enables additional feedback during program operation including packet sniffing")
var numRx = flag.Uint64("numRx", 1, "number of RX queues")
var numTx = flag.Uint64("numTx", 1, "number of TX queues")
var bSize = flag.Int("b", 256, "Batch Size for the driver")
var tunDev = flag.String("tun", "", "Empty string uses the ixy link endpoint, non-empty string specifies the tun device to use instead. Ignores the pci address")
var tap = flag.Bool("tap", false, "use tap istead of tun. Doesn't do anything for an ixy endpoint")

type dirStats struct {
	packets uint64
	bytes   uint64
}
type nicRTStats struct {
	tx *dirStats
	rx *dirStats
}

func diffMpps(pktsNew, pktsOld uint64, nanos time.Duration) float64 {
	return float64(pktsNew-pktsOld) / 1000000.0 / (float64(nanos) / 1000000000.0)
}

func diffMbit(statsOld, stats *dirStats, nanos time.Duration) float64 {
	// take stuff on the wire into account, i.e., the preamble, SFD and IFG (20 bytes)
	return (float64(stats.bytes-statsOld.bytes)/1000000.0/(float64(nanos)/1000000000.0))*8 + diffMpps(stats.packets, statsOld.packets, nanos)
}

func printStatsDiff(statsOld, stats *nicRTStats, nanos time.Duration) {
	var devString string
	if *tunDev != "" {
		devString = fmt.Sprintf("tun|'%v'", *tunDev)
	} else {
		devString = fmt.Sprintf("ixy|%v", flag.Arg(2))
	}
	fmt.Printf("Stack.NIC stats:\n")
	fmt.Printf("[%v] RX: %.2f Mbit/s %.2f Mpps\n", devString, diffMbit(statsOld.rx, stats.rx, nanos), diffMpps(stats.rx.packets, statsOld.rx.packets, nanos))
	fmt.Printf("[%v] TX: %.2f Mbit/s %.2f Mpps\n", devString, diffMbit(statsOld.tx, stats.tx, nanos), diffMpps(stats.tx.packets, statsOld.tx.packets, nanos))
}

func loadNICStats(stats stack.NICStats) *nicRTStats {
	return &nicRTStats{
		rx: &dirStats{
			packets: stats.Rx.Packets.Value(),
			bytes:   stats.Rx.Bytes.Value(),
		},
		tx: &dirStats{
			packets: stats.Tx.Packets.Value(),
			bytes:   stats.Tx.Bytes.Value(),
		},
	}
}

func readData(ch chan struct{}, noCheck bool, wq *waiter.Queue, ep tcpip.Endpoint, lenience uint) {
	// Read data and check whether it matches the sent data
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)
	expected := 0
	select {
	case <-ch:
		return
	default:
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
			// Check received data: content starts with 0 and counts upward
			if !noCheck {
				rec := binary.BigEndian.Uint64(v)
				interval := (1 << lenience) - 1
				if rec < uint64(expected)-uint64(interval) || rec > uint64(expected)+uint64(interval) {
					log.Fatalf("Received %v, expected %v +- %v.", rec, expected, interval)
				}
				expected++
			}
		}
	}
}

// echo reads from the tcp endpoint and echoes the received messages
func echo(wq *waiter.Queue, ep tcpip.Endpoint, tProto tcpip.TransportProtocolNumber) {
	if tProto == tcp.ProtocolNumber {
		defer ep.Close()
	} else if tProto != udp.ProtocolNumber {
		log.Fatalf("Calling echo with invalid Transport Protocol: %v", tProto)
	}

	// Create wait queue entry that notifies a channel.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	var addr tcpip.FullAddress
	f := func() *tcpip.FullAddress {
		if tProto == tcp.ProtocolNumber {
			return nil
		} else {
			return &addr
		}
	}

	for {
		v, _, err := ep.Read(f())
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}
			if tProto == udp.ProtocolNumber {
				log.Fatal("Read error: ", err)
			}
			return
		}
		ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{To: f()})
	}
}

// writer reads from standard input and writes to the endpoint until standard
// input is closed. It signals that it's done by closing the provided channel.
func writer(ch chan struct{}, ep tcpip.Endpoint, writeOpts tcpip.WriteOptions) {
	defer func() {
		ep.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()
	val := uint64(0)
	for {
		// one could implement randomized contents here but I don't see any benefits
		// keep the packet size small -> one
		v := buffer.NewView(8)
		binary.BigEndian.PutUint64(v, val)
		val++
		v.CapLength(8)
		for len(v) > 0 {
			n, _, err := ep.Write(tcpip.SlicePayload(v), writeOpts)
			// we can busy wait as sending packets is the only thing we want to do anyways
			if err != nil && err != tcpip.ErrWouldBlock {
				fmt.Println("Write failed:", err)
				return
			}
			v.TrimFront(int(n))
		}
	}
}

func main() {
	flag.Parse()
	if len(flag.Args()) < 5 {
		log.Fatal("Usage: ", os.Args[0], " <srv|clnt> <tcp|udp> <pci-address> <local-address> <local-port> <remote-address> <remote-port>\n"+
			"In server mode, the remote address and port will be ignored and do not have to be provided.")
	}
	var server bool
	if flag.Arg(0) == "s" || flag.Arg(0) == "srv" || flag.Arg(0) == "server" {
		server = true
	} else if flag.Arg(0) == "c" || flag.Arg(0) == "clnt" || flag.Arg(0) == "client" {
		server = false
	} else {
		log.Fatal("Did not provide a valid argument for server/client.\nValid arguments: \"s\", \"srv\", \"server\", \"c\", \"clnt\", \"client\".")
	}
	if !server && len(flag.Args()) != 7 {
		log.Fatal("Usage: ", os.Args[0], " <srv|clnt> <tcp|udp> <pci-address> <local-address> <local-port> <remote-address> <remote-port>")
	}
	var tProto tcpip.TransportProtocolNumber
	var tProtoName string
	if flag.Arg(1) == "tcp" {
		tProto = tcp.ProtocolNumber
		tProtoName = tcp.ProtocolName
	} else if flag.Arg(1) == "udp" {
		tProto = udp.ProtocolNumber
		tProtoName = udp.ProtocolName
	} else {
		log.Fatal("Did not provide a valid argument for the transport protocol.\nValid arguments: \"tcp\", \"udp\".")
	}

	if *verbose {
		if server {
			fmt.Printf("Creating a %v echo server.\n", tProtoName)
		} else {
			fmt.Printf("Creating a client to connect to a %v echo server.\n", tProtoName)
		}
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
	pciAddr := flag.Arg(2)
	addrName := flag.Arg(3)
	portName := flag.Arg(4)
	var remoteAddrName string
	var remotePortName string
	if !server {
		remoteAddrName = flag.Arg(5)
		remotePortName = flag.Arg(6)
	}
	nId := tcpip.NICID(1)

	rand.Seed(time.Now().UnixNano())

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	// Parse the IP address. Support both ipv4 and ipv6.creatcreat
	parsedAddr := net.ParseIP(addrName)
	if parsedAddr == nil {
		log.Fatalf("Bad IP address: %v", addrName)
	}
	var parsedRemoteAddr net.IP
	if !server {
		parsedRemoteAddr = net.ParseIP(remoteAddrName)
		if parsedRemoteAddr == nil {
			log.Fatalf("Bad remote IP address: %v", remoteAddrName)
		}
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

	remote := tcpip.FullAddress{
		NIC: tcpip.NICID(nId),
	}
	if !server {
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
	}

	var localPort uint16
	if v, err := strconv.Atoi(portName); err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	} else {
		localPort = uint16(v)
	}
	if !server {
		if v, err := strconv.Atoi(remotePortName); err != nil {
			log.Fatalf("Unable to convert port %v: %v", remotePortName, err)
		} else {
			remote.Port = uint16(v)
		}
	}

	// Create the stack with IP and TCP protocols, then add an ixy-based
	// NIC and address. Also add a stats counter to the stack.
	//stats := tcpip.Stats{}
	var netStr []string
	if server {
		netStr = []string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}
	} else {
		netStr = []string{ipv4.ProtocolName, ipv6.ProtocolName}
	}
	s := stack.New(netStr, []string{tProtoName}, stack.Options{ /*Stats: stats*/ })

	mtu := uint32(1500)

	var linkID tcpip.LinkEndpointID
	if *tunDev == "" {
		// Initialize ixgbe device
		var dev driver.IxyInterface
		func() {
			// mute prints from the driver when not in verbose mode
			if !*verbose {
				null, _ := os.Open(os.DevNull)
				sout := os.Stdout
				os.Stdout = null
				defer func() {
					os.Stdout = sout
					null.Close()
				}()
			}
			dev = driver.IxyInit(pciAddr, numRx16, numTx16)
		}()

		if *verbose {
			fmt.Printf("Initialized the ixy driver with PCI Address: %v, #RxQueues: %v, #TxQueues: %v\n", pciAddr, numRx16, numTx16)
		}

		linkID, err = ixygo.New(&ixygo.Options{
			Dev:            dev,
			TxEntries:      0, // uses default
			MTU:            mtu,
			EthernetHeader: true,
			Address:        tcpip.LinkAddress(maddr),
			GSOMaxSize:     0, // ignored, always set to zero as ixy.go doesn't support GSO
			DropTx:         false,
			BatchSize:      *bSize,
		})
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// fdbased enpoint using a tun/tap device
		mtu, err := rawfile.GetMTU(*tunDev)
		if err != nil {
			log.Fatal(err)
		}

		var fd int
		if *tap {
			fd, err = tun.OpenTAP(*tunDev)
		} else {
			fd, err = tun.Open(*tunDev)
		}
		if err != nil {
			log.Fatal(err)
		}

		linkID, err = fdbased.New(&fdbased.Options{
			FDs:            []int{fd},
			MTU:            mtu,
			EthernetHeader: *tap,
			Address:        tcpip.LinkAddress(maddr),
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	if *verbose {
		if err := s.CreateNIC(nId, sniffer.New(linkID)); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := s.CreateNIC(nId, linkID); err != nil {
			log.Fatal(err)
		}
	}

	if err := s.AddAddress(nId, proto, addr); err != nil {
		log.Fatal(err)
	}
	if server {
		if err := s.AddAddress(nId, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
			log.Fatal(err)
		}
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
			NIC:         nId,
		},
	})

	if *verbose {
		fmt.Println("Added default entry to the routing table.")
	}

	// Create UDP/TCP endpoint, (bind it), then start listening/sending stuff.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tProto, proto, &wq)
	if err != nil {
		log.Fatal(e)
	}

	defer ep.Close()

	// Bind if a port is specified.
	if localPort != 0 {
		if err := ep.Bind(tcpip.FullAddress{NIC: 0, Addr: "", Port: localPort}); err != nil {
			log.Fatal("Bind failed: ", err)
		}
	} else if server {
		log.Fatal("Did not specify a local port for the server to run on")
	}

	// start listening on a TCP server
	if tProto == tcp.ProtocolNumber && server {
		if err := ep.Listen(10); err != nil {
			log.Fatal("Listen failed: ", err)
		}
	}

	if *verbose {
		var prnt string
		if server {
			prnt = "server"
		} else {
			prnt = "client"
		}
		fmt.Printf("Setup complete, starting the %v %v:\n", tProtoName, prnt)
		if server {
			fmt.Printf("\tLocal address: %v:%v.\n", addr, localPort)
		} else {
			fmt.Printf("\tLocal address %v:%v, remote address %v:%v\n", addr, localPort, remote.Addr.String(), remote.Port)
		}
	}

	/*
	 *  Print stats:
	 *  prints every 1s
	 *  same format as in the fwd example for the ixy driver
	 */
	nicStatsInfo := s.NICInfo()[nId].Stats
	stats := loadNICStats(nicStatsInfo)
	var statsOld *nicRTStats
	lastStatsPrinted := time.Now()
	go func() {
		for {
			t := time.NewTimer(time.Second)
			currTime := <-t.C
			nicStatsInfo = s.NICInfo()[nId].Stats
			statsOld = stats
			stats = loadNICStats(nicStatsInfo)
			go printStatsDiff(statsOld, stats, currTime.Sub(lastStatsPrinted))
			lastStatsPrinted = currTime
		}
	}()

	if server {
		if tProto == tcp.ProtocolNumber {
			// tcp server: accept incoming connections and echo data
			// Wait for connections to appear.
			waitEntry, notifyCh := waiter.NewChannelEntry(nil)
			wq.EventRegister(&waitEntry, waiter.EventIn)
			defer wq.EventUnregister(&waitEntry)
			for {
				n, wq, err := ep.Accept()
				if err != nil {
					if err == tcpip.ErrWouldBlock {
						<-notifyCh
						continue
					}
					log.Fatal("Accept() failed:", err)
				}
				go echo(wq, n, tProto)
			}

		} else {
			// udp: echo incoming packets
			echo(&wq, ep, tProto)
		}

	} else {
		// Client: (connect &) send
		if tProto == tcp.ProtocolNumber {
			waitEntry, notifyCh := waiter.NewChannelEntry(nil)
			wq.EventRegister(&waitEntry, waiter.EventOut)
			// TCP client: connect
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
			go writer(writerCompletedCh, ep, tcpip.WriteOptions{})
			readData(writerCompletedCh, false, &wq, ep, 1)

			if *verbose {
				fmt.Println("Connection closed, shutting down.")
			}
			ep.Close()
		} else {
			// UDP client: send data
			writerCompletedCh := make(chan struct{})
			go writer(writerCompletedCh, ep, tcpip.WriteOptions{To: &remote})
			readData(writerCompletedCh, false, &wq, ep, 5)
			ep.Close()
		}
	}
}
