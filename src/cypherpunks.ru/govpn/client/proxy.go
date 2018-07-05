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
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"

	"cypherpunks.ru/govpn"
)

func (c *Client) proxyTCP() {
	proxyAddr, err := net.ResolveTCPAddr("tcp", c.config.ProxyAddress)
	if err != nil {
		c.Error <- err
		return
	}
	conn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		c.Error <- err
		return
	}
	req := "CONNECT " + c.config.ProxyAddress + " HTTP/1.1\n"
	req += "Host: " + c.config.ProxyAddress + "\n"
	if c.config.ProxyAuthentication != "" {
		req += "Proxy-Authorization: Basic "
		req += base64.StdEncoding.EncodeToString([]byte(c.config.ProxyAuthentication)) + "\n"
	}
	req += "\n"
	conn.Write([]byte(req))
	resp, err := http.ReadResponse(
		bufio.NewReader(conn),
		&http.Request{Method: "CONNECT"},
	)
	if err != nil || resp.StatusCode != http.StatusOK {
		c.Error <- fmt.Errorf("Unexpected response from proxy: %s", err.Error())
		return
	}
	govpn.Printf(`[proxy-connected remote="%s" addr="%s"]`, c.config.RemoteAddress, *proxyAddr)
	go c.handleTCP(conn)
}
