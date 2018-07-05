// +build linux

/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>
*/

package govpn

import (
	"io"
	"strings"

	"github.com/bigeagle/water"
)

func newTAPer(ifaceName string) (io.ReadWriter, error) {
	if strings.HasPrefix(ifaceName, "tap") {
		return water.NewTAP(ifaceName)
	} else {
		return water.NewTUN(ifaceName)
	}
}
