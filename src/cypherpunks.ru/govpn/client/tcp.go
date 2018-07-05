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

package client

import (
	"bytes"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"cypherpunks.ru/govpn"
)

func (c *Client) startTCP() {
	remote, err := net.ResolveTCPAddr("tcp", c.config.RemoteAddress)
	if err != nil {
		c.Error <- fmt.Errorf("Can not resolve remote address: %s", err)
		return
	}
	conn, err := net.DialTCP("tcp", nil, remote)
	if err != nil {
		c.Error <- fmt.Errorf("Can not connect to address: %s", err)
		return
	}
	govpn.Printf(`[connected remote="%s"]`, c.config.RemoteAddress)
	c.handleTCP(conn)
}

func (c *Client) handleTCP(conn *net.TCPConn) {
	hs := govpn.HandshakeStart(c.config.RemoteAddress, conn, c.config.Peer)
	buf := make([]byte, 2*(govpn.EnclessEnlargeSize+c.config.MTU)+c.config.MTU)
	var n int
	var err error
	var prev int
	var peer *govpn.Peer
	var terminator chan struct{}
HandshakeCycle:
	for {
		select {
		case <-c.termination:
			break HandshakeCycle
		default:
		}
		if prev == len(buf) {
			govpn.Printf(`[packet-timeouted remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break HandshakeCycle
		}

		if err = conn.SetReadDeadline(time.Now().Add(c.config.Peer.Timeout)); err != nil {
			c.Error <- err
			break HandshakeCycle
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			govpn.Printf(`[connection-timeouted remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break HandshakeCycle
		}

		prev += n
		peerID := c.idsCache.Find(buf[:prev])
		if peerID == nil {
			continue
		}
		peer = hs.Client(buf[:prev])
		prev = 0
		if peer == nil {
			continue
		}
		govpn.Printf(`[handshake-completed remote="%s"]`, c.config.RemoteAddress)
		c.knownPeers.Store(c.config.RemoteAddress, &peer)
		if c.firstUpCall {
			go govpn.ScriptCall(c.config.UpPath, c.config.InterfaceName, c.config.RemoteAddress)
			c.firstUpCall = false
		}
		hs.Zero()
		terminator = make(chan struct{})
		go govpn.PeerTapProcessor(peer, c.tap, terminator)
		break HandshakeCycle
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	prev = 0
	var i int
TransportCycle:
	for {
		select {
		case <-c.termination:
			break TransportCycle
		default:
		}
		if prev == len(buf) {
			govpn.Printf(`[packet-timeouted remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		if err = conn.SetReadDeadline(time.Now().Add(c.config.Peer.Timeout)); err != nil {
			c.Error <- err
			break TransportCycle
		}
		n, err = conn.Read(buf[prev:])
		if err != nil {
			govpn.Printf(`[connection-timeouted remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		prev += n
	CheckMore:
		if prev < govpn.MinPktLength {
			continue
		}
		i = bytes.Index(buf[:prev], peer.NonceExpect)
		if i == -1 {
			continue
		}
		if !peer.PktProcess(buf[:i+govpn.NonceSize], c.tap, false) {
			govpn.Printf(`[packet-unauthenticated remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break TransportCycle
		}
		if atomic.LoadUint64(&peer.BytesIn)+atomic.LoadUint64(&peer.BytesOut) > govpn.MaxBytesPerKey {
			govpn.Printf(`[rehandshake-required remote="%s"]`, c.config.RemoteAddress)
			c.rehandshaking <- struct{}{}
			break TransportCycle
		}
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	if terminator != nil {
		terminator <- struct{}{}
	}
	peer.Zero()
	if err = conn.Close(); err != nil {
		c.Error <- err
	}
}
