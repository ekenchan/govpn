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

// Simple secure, DPI/censorship-resistant free software VPN daemon client.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"cypherpunks.ru/govpn"
	"cypherpunks.ru/govpn/client"
)

func main() {
	var (
		remoteAddr  = flag.String("remote", "", "Remote server address")
		proto       = flag.String("proto", "udp", "Protocol to use: udp or tcp")
		ifaceName   = flag.String("iface", "tap0", "TUN/TAP network interface")
		verifierRaw = flag.String("verifier", "", "Verifier")
		keyPath     = flag.String("key", "", "Path to passphrase file")
		upPath      = flag.String("up", "", "Path to up-script")
		downPath    = flag.String("down", "", "Path to down-script")
		stats       = flag.String("stats", "", "Enable stats retrieving on host:port")
		proxyAddr   = flag.String("proxy", "", "Use HTTP proxy on host:port")
		proxyAuth   = flag.String("proxy-auth", "", "user:password Basic proxy auth")
		mtu         = flag.Int("mtu", govpn.MTUDefault, "MTU of TUN/TAP interface")
		timeoutP    = flag.Int("timeout", 60, "Timeout seconds")
		timeSync    = flag.Int("timesync", 0, "Time synchronization requirement")
		noreconnect = flag.Bool("noreconnect", false, "Disable reconnection after timeout")
		noisy       = flag.Bool("noise", false, "Enable noise appending")
		encless     = flag.Bool("encless", false, "Encryptionless mode")
		cpr         = flag.Int("cpr", 0, "Enable constant KiB/sec out traffic rate")
		egdPath     = flag.String("egd", "", "Optional path to EGD socket")
		syslog      = flag.Bool("syslog", false, "Enable logging to syslog")
		version     = flag.Bool("version", false, "Print version information")
		warranty    = flag.Bool("warranty", false, "Print warranty information")
		protocol    client.Protocol
		err         error
	)

	flag.Parse()
	if *warranty {
		fmt.Println(govpn.Warranty)
		return
	}
	if *version {
		fmt.Println(govpn.VersionGet())
		return
	}
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	switch *proto {
	case "udp":
		protocol = client.ProtocolUDP
	case "tcp":
		protocol = client.ProtocolTCP
	default:
		log.Fatalln("Unknown protocol specified")
	}

	if *proxyAddr != "" && protocol == client.ProtocolUDP {
		log.Fatalln("HTTP proxy is supported only in TCP mode")
	}

	if *verifierRaw == "" {
		log.Fatalln("-verifier is required")
	}
	verifier, err := govpn.VerifierFromString(*verifierRaw)
	if err != nil {
		log.Fatalln("Invalid -verifier:", err)
	}
	key, err := govpn.KeyRead(*keyPath)
	if err != nil {
		log.Fatalln("Invalid -key:", err)
	}
	priv := verifier.PasswordApply(key)
	if *encless {
		if protocol != client.ProtocolTCP {
			log.Fatalln("Currently encryptionless mode works only with TCP")
		}
		*noisy = true
	}
	conf := client.Configuration{
		PrivateKey: priv,
		Peer: &govpn.PeerConf{
			ID:       verifier.ID,
			Iface:    *ifaceName,
			MTU:      *mtu,
			Timeout:  time.Second * time.Duration(*timeoutP),
			TimeSync: *timeSync,
			Noise:    *noisy,
			CPR:      *cpr,
			Encless:  *encless,
			Verifier: verifier,
			DSAPriv:  priv,
		},
		Protocol:            protocol,
		InterfaceName:       *ifaceName,
		ProxyAddress:        *proxyAddr,
		ProxyAuthentication: *proxyAuth,
		RemoteAddress:       *remoteAddr,
		UpPath:              *upPath,
		DownPath:            *downPath,
		StatsAddress:        *stats,
		NoReconnect:         *noreconnect,
		MTU:                 *mtu,
	}
	if err = conf.Validate(); err != nil {
		log.Fatalln("Invalid settings:", err)
	}

	log.Println(govpn.VersionGet())

	if *syslog {
		govpn.SyslogEnable()
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)
	c := client.NewClient(conf, verifier, termSignal)
	go c.MainCycle()
	if err = <-c.Error; err != nil {
		log.Fatalln(err)
	}
}
