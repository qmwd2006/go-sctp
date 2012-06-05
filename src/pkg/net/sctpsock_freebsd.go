package net

import (
  "os"
	"syscall"
)

func ListenSCTP(net string, laddr *SCTPAddr) (conn *SCTPConn, err error) {
  switch net {
  case "sctp", "sctp4", "sctp6":
  default:
    return nil, UnknownNetworkError(net)
  }
  if laddr == nil {
    return nil, &OpError{"listen", net, nil, errMissingAddress}
  }
	fd, err := internetSocket(net, laddr.toAddr(), nil, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP, "listen", sockaddrToSCTP)
	if err != nil {
		return nil, err
	}
  conn = newSCTPConn(fd)
  conn.SetInitMsg()

	err = syscall.Listen(fd.sysfd, listenerBacklog)
	if err != nil {
		closesocket(fd.sysfd)
		return nil, &OpError{"listen", net, laddr, err}
	}
	return conn, nil
}
