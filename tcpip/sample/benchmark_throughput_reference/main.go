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
	"net"
	"os"
	"strconv"
	"time"

	"github.com/SebastianVoit/netstack/tcpip"
	"github.com/SebastianVoit/netstack/tcpip/stack"
)

// var verbose = flag.Bool("v", false, "the verbose flag enables additional feedback during program operation including packet sniffing")
var paylSize = flag.Int("ps", 1, "Payload size for the packets send by the client as a multiple of 8B. Max MSS, <=0 -> MSS.")
var iFace = flag.String("iface", "", "The interface whose mtu should be used for capping mss.")

type dirStats struct {
	bytes   uint64
	packets uint64
}

type l4Stats struct {
	tx *dirStats
	rx *dirStats
}

func loadL4Stats(stats stack.NICStats) *l4Stats {
	return &l4Stats{
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

func diffMpps(pktsNew, pktsOld uint64, nanos time.Duration) float64 {
	return float64(pktsNew-pktsOld) / 1000000.0 / (float64(nanos) / 1000000000.0)
}

func diffMbit(statsOld, stats *dirStats, nanos time.Duration, ipVer int, tProto string) float64 {
	// take stuff on the wire into account, i.e., the preamble, SFD and IFG (20 bytes)
	// take headers into account (assume minimum sized):
	l2 := 14 + 4 // header + FCS
	l3v4 := 20
	l3v6 := 40
	l4u := 8
	l4t := 20
	hdrB := l2
	if ipVer == 4 {
		hdrB += l3v4
	}
	if ipVer == 6 {
		hdrB += l3v6
	}
	if tProto == "udp" {
		hdrB += l4u
	}
	if tProto == "tcp" {
		hdrB += l4t
	}
	return (float64(stats.bytes-statsOld.bytes)/1000000.0/(float64(nanos)/1000000000.0))*8 + diffMpps(stats.packets, statsOld.packets, nanos)*(20+float64(hdrB))*8
}

func diffMbitPl(statsOld, stats *dirStats, nanos time.Duration) float64 {
	// only take actually transported data into account
	return float64(stats.bytes-statsOld.bytes) / 1000000.0 / (float64(nanos) / 1000000000.0) * 8
}

func printStatsDiff(statsOld, stats *l4Stats, nanos time.Duration, ipVer int, tProto string) {
	devString := "OS stack"
	fmt.Printf("L4 stats + minimum header sizes:\n")
	fmt.Printf("[%v] RX: %.2f Mbit/s (total) %.2f Mbit/s (payload)  %.2f Mpps\n", devString, diffMbit(statsOld.rx, stats.rx, nanos, ipVer, tProto), diffMbitPl(statsOld.tx, stats.tx, nanos), diffMpps(stats.rx.packets, statsOld.rx.packets, nanos))
	fmt.Printf("[%v] TX: %.2f Mbit/s (total) %.2f Mbit/s (payload)  %.2f Mpps\n", devString, diffMbit(statsOld.tx, stats.tx, nanos, ipVer, tProto), diffMbitPl(statsOld.tx, stats.tx, nanos), diffMpps(stats.tx.packets, statsOld.tx.packets, nanos))
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 4 {
		log.Fatal("Usage: ", os.Args[0], " <srv|clnt> <tcp|udp> <address> <port>\n")
	}
	var server bool
	if flag.Arg(0) == "s" || flag.Arg(0) == "srv" || flag.Arg(0) == "server" {
		server = true
	} else if flag.Arg(0) == "c" || flag.Arg(0) == "clnt" || flag.Arg(0) == "client" {
		server = false
	} else {
		log.Fatal("Did not provide a valid argument for server/client.\nValid arguments: \"s\", \"srv\", \"server\", \"c\", \"clnt\", \"client\".")
	}
	tProtoName := flag.Arg(1)
	if tProtoName != "tcp" && tProtoName != "udp" {
		log.Fatal("Did not provide a valid argument for the transport protocol.\nValid arguments: \"tcp\", \"udp\".")
	}

	var addr net.IP
	var port int
	var ipVer int
	addr = net.ParseIP(flag.Arg(2))
	if addr == nil {
		log.Fatalf("Bad local IP: %v", flag.Arg(2))
	}
	if addr.To4() != nil {
		ipVer = 4
	} else {
		ipVer = 6
	}
	port, err := strconv.Atoi(flag.Arg(3))
	if err != nil {
		log.Fatalf("Bad local Port: %v", flag.Arg(3))
	}

	/*
	 * Printer:
	 * count packets + bytes
	 * then calc Mbit & Mpps like the benchmark
	 * Note: factor in headers (L2-4)
	 */
	stats := stack.NICStats{
		Tx: stack.DirectionStats{
			Packets: &tcpip.StatCounter{},
			Bytes:   &tcpip.StatCounter{},
		},
		Rx: stack.DirectionStats{
			Packets: &tcpip.StatCounter{},
			Bytes:   &tcpip.StatCounter{},
		},
	}
	statsCurr := loadL4Stats(stats)
	var statsOld *l4Stats
	lastStatsPrinted := time.Now()
	go func() {
		for {
			t := time.NewTimer(time.Second)
			currTime := <-t.C
			statsOld = statsCurr
			statsCurr = loadL4Stats(stats)
			go printStatsDiff(statsOld, statsCurr, currTime.Sub(lastStatsPrinted), ipVer, tProtoName)
			lastStatsPrinted = currTime
		}
	}()

	mtu := 1500 // default of 1500

	iFc, err := net.InterfaceByName(*iFace)
	if err != nil {
		fmt.Printf("Couldn't get interface by name, using default. Error: %v\n", err)
	} else {
		mtu = iFc.MTU
	}
	mss := mtu
	if ipVer == 4 {
		mss -= 20
	} else {
		mss -= 40
	}
	if tProtoName == "tcp" {
		mss -= 20
	} else {
		mss -= 8
	}
	if *paylSize*8 > int(mss) || *paylSize <= 0 {
		*paylSize = int((mss - mss%8) / 8) // paylSize has to be a multiple of 8
	}

	// also this is probably managable without implementing everything twice
	var errSrc string
	if server {
		if tProtoName == "tcp" {
			// TCP echo server
			errSrc = "TCP server: "
			localAddr := net.TCPAddr{IP: addr, Port: port}
			conn, err := net.ListenTCP(tProtoName, &localAddr)
			if err != nil {
				log.Fatalf("%vconnect error: %v", errSrc, err)
			}
			defer conn.Close()
			for {
				// accept connection and start echo goroutine
				tConn, err := conn.AcceptTCP()
				if err != nil {
					log.Fatalf("%vnet.AcceptTCP() error: %v", errSrc, err)
				}
				go func(c *net.TCPConn) {
					defer c.Close()
					b := make([]byte, 2048)
					for {
						// read packets
						n, rerr := c.Read(b)
						if err != nil {
							log.Fatalf("%vTCPConn.Read() error: %v", errSrc, rerr)
						}
						// increment stats
						stats.Rx.Packets.Increment()
						stats.Rx.Bytes.IncrementBy(uint64(n))
						// echo
						n, werr := c.Write(b[:n])
						if werr != nil {
							log.Fatalf("%vTCPConn.Write() error: %v", errSrc, werr)
						}
						// increment stats
						stats.Tx.Packets.Increment()
						stats.Tx.Bytes.IncrementBy(uint64(n))
					}
				}(tConn)
			}
		} else {
			// UDP echo server
			errSrc = "UDP server: "
			localAddr := net.UDPAddr{IP: addr, Port: port}
			conn, err := net.ListenUDP(tProtoName, &localAddr)
			if err != nil {
				log.Fatalf("%vconnect error: %v", errSrc, err)
			}
			defer conn.Close()
			b := make([]byte, 2048)
			for {
				// read packets
				n, remoteAddr, rerr := conn.ReadFromUDP(b)
				if rerr != nil {
					log.Fatalf("%vnet.ReadFromUDP() error: %v", errSrc, rerr)
				}
				// incement stats
				stats.Rx.Packets.Increment()
				stats.Rx.Bytes.IncrementBy(uint64(n))
				// echo
				n, werr := conn.WriteTo(b[:n], remoteAddr)
				if werr != nil {
					log.Fatalf("%vnet.WriteTo() error: %v", errSrc, werr)
				}
				// increment stats
				stats.Tx.Packets.Increment()
				stats.Tx.Bytes.IncrementBy(uint64(n))
			}
		}
	} else {
		if tProtoName == "tcp" {
			// TCP client
			errSrc = "TCP client: "

		} else {
			// UDP client
			errSrc = "UDP client: "
		}
		addrStr := fmt.Sprintf("%v:%v", addr.String(), port)
		conn, err := net.Dial(tProtoName, addrStr)
		if err != nil {
			log.Fatalf("%vnet.Dial() error: %v", errSrc, err)
		}
		b := make([]byte, 8*(*paylSize))

		// fetch incoming packets
		go func() {
			rec := make([]byte, 2048)
			n, rerr := conn.Read(rec)
			if rerr != nil {
				log.Fatalf("%vnet.Read() error: %v", errSrc, rerr)
			}
			if n != 8 {
				fmt.Printf("%vSuspivious packet of wrong size: Should be %v Bytes, is %v.\nPacket:\n%v", errSrc, 8, n, rec)
			}
			stats.Rx.Packets.Increment()
			stats.Rx.Bytes.IncrementBy(uint64(n))
		}()
		// flood packets out
		sent := uint64(0)
		for {
			binary.BigEndian.PutUint64(b, sent) // only set the first byte to keep non-sending computation low
			n, werr := conn.Write(b)
			if err != nil {
				log.Fatalf("%vnet.Write() error: %v", errSrc, werr)
			}
			stats.Tx.Packets.Increment()
			stats.Tx.Bytes.IncrementBy(uint64(n))
			sent++
		}
	}
}
