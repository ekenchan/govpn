/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Simple secure, DPI/censorship-resistant free software VPN daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"cypherpunks.ru/govpn"
)

var (
	bindAddr = flag.String("bind", "[::]:1194", "Bind to address")
	proto    = flag.String("proto", "udp", "Protocol to use: udp, tcp or all")
	confPath = flag.String("conf", "peers.yaml", "Path to configuration YAML")
	stats    = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxy    = flag.String("proxy", "", "Enable HTTP proxy on host:port")
	egdPath  = flag.String("egd", "", "Optional path to EGD socket")
	syslog   = flag.Bool("syslog", false, "Enable logging to syslog")
	version  = flag.Bool("version", false, "Print version information")
	warranty = flag.Bool("warranty", false, "Print warranty information")
)

func main() {
	flag.Parse()
	if *warranty {
		fmt.Println(govpn.Warranty)
		return
	}
	if *version {
		fmt.Println(govpn.VersionGet())
		return
	}
	timeout := time.Second * time.Duration(govpn.TimeoutDefault)
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println(govpn.VersionGet())

	confInit()

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	if *syslog {
		govpn.SyslogEnable()
	}

	switch *proto {
	case "udp":
		startUDP()
	case "tcp":
		startTCP()
	case "all":
		startUDP()
		startTCP()
	default:
		log.Fatalln("Unknown protocol specified")
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}
	if *proxy != "" {
		go proxyStart()
	}
	govpn.BothPrintf(`[started bind="%s"]`, *bindAddr)

	var needsDeletion bool
MainCycle:
	for {
		select {
		case <-termSignal:
			govpn.BothPrintf(`[terminating bind="%s"]`, *bindAddr)
			peers.Range(func(_, psI interface{}) bool {
				ps := psI.(*PeerState)
				govpn.ScriptCall(
					confs[*ps.peer.ID].Down,
					ps.tap.Name,
					ps.peer.Addr,
				)
				return true
			})
			break MainCycle
		case <-hsHeartbeat:
			now := time.Now()

			handshakes.Range(func(addrI, hsI interface{}) bool {
				addr := addrI.(string)
				hs := hsI.(*govpn.Handshake)
				if hs.LastPing.Add(timeout).Before(now) {
					govpn.Printf(`[handshake-delete bind="%s" addr="%s"]`, *bindAddr, addr)
					hs.Zero()
					handshakes.Delete(addr)
				}
				return true
			})

			peers.Range(func(addrI, psI interface{}) bool {
				addr := addrI.(string)
				ps := psI.(*PeerState)
				ps.peer.BusyR.Lock()
				needsDeletion = ps.peer.LastPing.Add(timeout).Before(now)
				ps.peer.BusyR.Unlock()
				if needsDeletion {
					govpn.Printf(
						`[peer-delete bind="%s" peer="%s"]`,
						*bindAddr,
						ps.peer.ID.String(),
					)
					peers.Delete(addr)
					knownPeers.Delete(addr)
					peersByID.Delete(*ps.peer.ID)
					go govpn.ScriptCall(
						confs[*ps.peer.ID].Down,
						ps.tap.Name,
						ps.peer.Addr,
					)
					ps.terminator <- struct{}{}
				}
				return true
			})
		}
	}
}
