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

package main

import (
	"log"
	"net"

	"cypherpunks.ru/govpn"
)

type UDPSender struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (c UDPSender) Write(data []byte) (int, error) {
	return c.conn.WriteToUDP(data, c.addr)
}

var (
	// Buffers for UDP parallel processing
	udpBufs = make(chan []byte, 1<<8)
)

func startUDP() {
	bind, err := net.ResolveUDPAddr("udp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		log.Fatalln("Can not listen on UDP:", err)
	}
	govpn.BothPrintf(`[udp-listen bind="%s"]`, *bindAddr)

	udpBufs <- make([]byte, govpn.MTUMax)
	go func() {
		var buf []byte
		var raddr *net.UDPAddr
		var addr string
		var n int
		var err error
		var exists bool
		var psI interface{}
		var ps *PeerState
		var hsI interface{}
		var hs *govpn.Handshake
		var addrPrevI interface{}
		var addrPrev string
		var peerPrevI interface{}
		var peerPrev *PeerState
		var peerID *govpn.PeerID
		var conf *govpn.PeerConf
		for {
			buf = <-udpBufs
			n, raddr, err = conn.ReadFromUDP(buf)
			if err != nil {
				govpn.Printf(`[receive-failed bind="%s" err="%s"]`, *bindAddr, err)
				break
			}
			addr = raddr.String()

			psI, exists = peers.Load(addr)
			if exists {
				ps = psI.(*PeerState)
				go func(peer *govpn.Peer, tap *govpn.TAP, buf []byte, n int) {
					peer.PktProcess(buf[:n], tap, true)
					udpBufs <- buf
				}(ps.peer, ps.tap, buf, n)
				continue
			}

			hsI, exists = handshakes.Load(addr)
			if !exists {
				peerID = idsCache.Find(buf[:n])
				if peerID == nil {
					govpn.Printf(`[identity-unknown bind="%s" addr="%s"]`, *bindAddr, addr)
					udpBufs <- buf
					continue
				}
				conf = confs[*peerID]
				if conf == nil {
					govpn.Printf(
						`[conf-get-failed bind="%s" peer="%s"]`,
						*bindAddr, peerID.String(),
					)
					udpBufs <- buf
					continue
				}
				hs := govpn.NewHandshake(
					addr,
					UDPSender{conn: conn, addr: raddr},
					conf,
				)
				hs.Server(buf[:n])
				udpBufs <- buf
				handshakes.Store(addr, hs)
				continue
			}

			hs = hsI.(*govpn.Handshake)
			peer := hs.Server(buf[:n])
			if peer == nil {
				udpBufs <- buf
				continue
			}
			govpn.Printf(
				`[handshake-completed bind="%s" addr="%s" peer="%s"]`,
				*bindAddr, addr, peerID.String(),
			)
			hs.Zero()
			handshakes.Delete(addr)

			go func() {
				udpBufs <- make([]byte, govpn.MTUMax)
				udpBufs <- make([]byte, govpn.MTUMax)
			}()
			addrPrevI, exists = peersByID.Load(*peer.ID)
			if exists {
				addrPrev = addrPrevI.(string)
				peerPrevI, exists = peers.Load(addrPrev)
				if exists {
					peerPrev = peerPrevI.(*PeerState)
					exists = peerPrev == nil
				}
			}
			if exists {
				peerPrev.terminator <- struct{}{}
				psNew := &PeerState{
					peer:       peer,
					tap:        peerPrev.tap,
					terminator: make(chan struct{}),
				}
				go func(peer *govpn.Peer, tap *govpn.TAP, terminator chan struct{}) {
					govpn.PeerTapProcessor(peer, tap, terminator)
					<-udpBufs
					<-udpBufs
				}(psNew.peer, psNew.tap, psNew.terminator)
				peers.Delete(addrPrev)
				peers.Store(addr, psNew)
				knownPeers.Delete(addrPrev)
				knownPeers.Store(addr, &peer)
				peersByID.Store(*peer.ID, addr)
				govpn.Printf(
					`[rehandshake-completed bind="%s" peer="%s"]`,
					*bindAddr, peer.ID.String(),
				)
			} else {
				go func(addr string, peer *govpn.Peer) {
					ifaceName, err := callUp(peer.ID, peer.Addr)
					if err != nil {
						return
					}
					tap, err := govpn.TAPListen(ifaceName, peer.MTU)
					if err != nil {
						govpn.Printf(
							`[tap-failed bind="%s" peer="%s" err="%s"]`,
							*bindAddr, peer.ID.String(), err,
						)
						return
					}
					psNew := &PeerState{
						peer:       peer,
						tap:        tap,
						terminator: make(chan struct{}),
					}
					go func(peer *govpn.Peer, tap *govpn.TAP, terminator chan struct{}) {
						govpn.PeerTapProcessor(peer, tap, terminator)
						<-udpBufs
						<-udpBufs
					}(psNew.peer, psNew.tap, psNew.terminator)
	                        	peers.Range(func(addrI, psI interface{}) bool {
						addr2 := addrI.(string)
		                                ps := psI.(*PeerState)
               			                if ps.peer.ID.String() == peer.ID.String() {
                                        		govpn.Printf(
                                                		`[peer-delete bind="%s" peer="%s"]`,
                                                		*bindAddr,
                                                		ps.peer.ID.String(),
                                        		)
                                        		peers.Delete(addr2)
                                        		knownPeers.Delete(addr2)
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

					peers.Store(addr, psNew)
					knownPeers.Store(addr, &peer)
					peersByID.Store(*peer.ID, addr)
					govpn.Printf(
						`[peer-created bind="%s" peer="%s"]`,
						*bindAddr,
						peer.ID.String(),
					)
				}(addr, peer)
			}
			udpBufs <- buf
		}
	}()
}
