// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd netbsd openbsd

// IP-level socket options for BSD variants

package net

import (
	"os"
	"syscall"
)

func ipv4MulticastTTL(fd *netFD) (int, error) {
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	v, err := syscall.GetsockoptByte(fd.sysfd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	return int(v), nil
}

func setIPv4MulticastTTL(fd *netFD, v int) error {
	if err := fd.incref(false); err != nil {
		return err
	}
	defer fd.decref()
	err := syscall.SetsockoptByte(fd.sysfd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, byte(v))
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func ipv6TrafficClass(fd *netFD) (int, error) {
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	v, err := syscall.GetsockoptInt(fd.sysfd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	return v, nil
}

func setIPv6TrafficClass(fd *netFD, v int) error {
	if err := fd.incref(false); err != nil {
		return err
	}
	defer fd.decref()
	err := syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, v)
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func setSCTPInitMsg(fd *netFD, sim *syscall.SCTPInitMsg) error {
	if err := fd.incref(false); err != nil {
		return err
	}
	defer fd.decref()
	err := syscall.SetsockoptSCTPInitMsg(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_INITMSG, sim)
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

func setNoDelaySCTP(fd *netFD, noDelay bool) error {
	if err := fd.incref(false); err != nil {
		return err
	}
	defer fd.decref()
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_NODELAY, boolint(noDelay)))
}

func setNotificationAssociationChange(fd *netFD, notify bool) error {
	if err := fd.incref(false); err != nil {
		return err
	}
  defer fd.decref()
  var event syscall.SCTPEvent
  event.Assoc_id = syscall.SCTP_FUTURE_ASSOC;
  event.Type = syscall.SCTP_ASSOC_CHANGE;
  event.On = uint8(boolint(notify));

  return os.NewSyscallError("setsockopt", syscall.SetsockoptSCTPEvent(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_EVENT, &event))
}

