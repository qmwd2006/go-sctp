// SCTP sockets

package net

import (
	"os"
//  "io"
	"syscall"
	"time"
)


// SCTPAddr represents the address of a SCTP end point
type SCTPAddr struct {
  IP  IP
  Port  int
}

type sctplisten interface {


}


// Network returns the address's network name, "sctp".
func (a *SCTPAddr) Network() string { return "sctp" }

func (a *SCTPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	return JoinHostPort(a.IP.String(), itoa(a.Port))
}

func (a *SCTPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (a *SCTPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}


func (a *SCTPAddr) sockaddr(family int) (syscall.Sockaddr, error) {
	return ipToSockaddr(family, a.IP, a.Port)
}

func (a *SCTPAddr) toAddr() sockaddr {
	if a == nil { // nil *SCTPAddr
		return nil // nil interface
	}
	return a
}

// SCTPConn is an implementation of the Conn interface
// for SCTP network connections.
type SCTPConn struct {
	fd *netFD
  stream uint16
}

func (c *SCTPConn) GetstreamId() uint16 {
  return c.stream
}

func newSCTPConn(fd *netFD) *SCTPConn {
	c := &SCTPConn{fd, 0}
	c.SetNoDelaySCTP(true)
	return c
}

func (c *SCTPConn) ok() bool { return c != nil && c.fd != nil }

// Implementation of the Conn interface - see Conn for documentation.

// Read implements the Conn Read method.
func (c *SCTPConn) Read(b []byte) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	return c.fd.Read(b)
}

// ReadFrom implements the io.ReaderFrom ReadFrom method.
//func (c *SCTPConn) ReadFrom(r io.Reader) (int64, error) {
//	if n, err, handled := sendFile(c.fd, r); handled {
//		return n, err
//	}
//	return genericReadFrom(c, r)
//}

// Write implements the Conn Write method.
func (c *SCTPConn) Write(b []byte) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	return c.fd.Write(b)
}

//func (c *SCTPConn)

// Close closes the SCTP connection.
func (c *SCTPConn) Close() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	err := c.fd.Close()
	c.fd = nil
	return err
}

// CloseRead shuts down the reading side of the SCTP connection.
// Most callers should just use Close.
func (c *SCTPConn) CloseRead() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return c.fd.CloseRead()
}

// CloseWrite shuts down the writing side of the SCTP connection.
// Most callers should just use Close.
func (c *SCTPConn) CloseWrite() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return c.fd.CloseWrite()
}

// LocalAddr returns the local network address, a *SCTPAddr.
func (c *SCTPConn) LocalAddr() Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.laddr
}

// RemoteAddr returns the remote network address, a *TCPAddr.
func (c *SCTPConn) RemoteAddr() Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.raddr
}

// SetDeadline implements the Conn SetDeadline method.
func (c *SCTPConn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setDeadline(c.fd, t)
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setReadDeadline(c.fd, t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setWriteDeadline(c.fd, t)
}

// SetReadBuffer sets the size of the operating system's
// receive buffer associated with the connection.
func (c *SCTPConn) SetReadBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setReadBuffer(c.fd, bytes)
}

// SetWriteBuffer sets the size of the operating system's
// transmit buffer associated with the connection.
func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setWriteBuffer(c.fd, bytes)
}

// SetLinger sets the behavior of Close() on a connection
// which still has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), Close returns immediately and
// the operating system finishes sending the data in the background.
//
// If sec == 0, Close returns immediately and the operating system
// discards any unsent or unacknowledged data.
//
// If sec > 0, Close blocks for at most sec seconds waiting for
// data to be sent and acknowledged.
func (c *SCTPConn) SetLinger(sec int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setLinger(c.fd, sec) // TODO
}

// SetKeepAlive sets whether the operating system should send
// keepalive messages on the connection.
func (c *SCTPConn) SetKeepAlive(keepalive bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	return setKeepAlive(c.fd, keepalive)
}

// File returns a copy of the underlying os.File, set to blocking mode.
// It is the caller's responsibility to close f when finished.
// Closing c does not affect f, and closing f does not affect c.
func (c *SCTPConn) File() (f *os.File, err error) { return c.fd.dup() }

// DialSCTP connects to the remote address raddr on the network net,
// which must be "sctp", "sctp4", or "sctp6".  If laddr is not nil, it is used
// as the local address for the connection.
func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, &OpError{"dial", net, nil, errMissingAddress}
	}

  // TODO difference between one-to-one and one-to-many
	fd, err := internetSocket(net, laddr.toAddr(), raddr.toAddr(), syscall.SOCK_SEQPACKET, 0, "implicit", sockaddrToSCTP)

	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}

func selfConnectSCTP(fd *netFD) bool {
	if fd.laddr == nil || fd.raddr == nil {
		return true
	}
	l := fd.laddr.(*SCTPAddr)
	r := fd.raddr.(*SCTPAddr)
	return l.Port == r.Port && l.IP.Equal(r.IP)
}

// SCTPListener is a SCTP network listener.
// Clients should typically use variables of type Listener
// instead of assuming SCTP.
type SCTPListener struct {
	fd *netFD
}

// ListenOneToOneSCTP announces on the SCTP address laddr and returns a SCTP listener.
// This is for one to one style sockets (similar to TCP, for full SCTP
// functionality use ListenSCTP
// Net must be "sctp", "sctp4", or "sctp6".
// If laddr has a port of 0, it means to listen on some available port.
// The caller can use l.Addr() to retrieve the chosen address.
func ListenOneToOneSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
  fd, err := internetSocket(net, laddr.toAddr(), nil, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP, "listen", sockaddrToSCTP)
  if err != nil {
    return nil, err
  }
  err = syscall.Listen(fd.sysfd, listenerBacklog)
  if err != nil {
    closesocket(fd.sysfd)
    return nil, &OpError{"listen", net, laddr, err}
  }
  l := new(SCTPListener)
  l.fd = fd
  return l, nil
}

// ListenSCTP can be used for one-to-many style SCTP sockets 
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

// AcceptSCTP accepts the next incoming call and returns the new connection
// and the remote address.
func (l *SCTPListener) AcceptSCTP() (c *SCTPConn, err error) {
	if l == nil || l.fd == nil || l.fd.sysfd < 0 {
		return nil, syscall.EINVAL
	}
	fd, err := l.fd.accept(sockaddrToSCTP)
	if err != nil {
		return nil, err
	}
	return newSCTPConn(fd), nil
}

// Accept implements the Accept method in the Listener interface;
// it waits for the next call and returns a generic Conn.
func (l *SCTPListener) Accept() (c Conn, err error) {
	c1, err := l.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	return c1, nil
}

// Close stops listening on the SCTP address.
// Already Accepted connections are not closed.
func (l *SCTPListener) Close() error {
	if l == nil || l.fd == nil {
		return syscall.EINVAL
	}
	return l.fd.Close()
}

// Addr returns the listener's network address, a *SCTPAddr.
func (l *SCTPListener) Addr() Addr { return l.fd.laddr }

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (l *SCTPListener) SetDeadline(t time.Time) error {
	if l == nil || l.fd == nil {
		return syscall.EINVAL
	}
	return setDeadline(l.fd, t)
}

// File returns a copy of the underlying os.File, set to blocking mode.
// It is the caller's responsibility to close f when finished.
// Closing c does not affect f, and closing f does not affect c.
func (l *SCTPListener) File() (f *os.File, err error) { return l.fd.dup() }

func sockaddrToSCTP(sa syscall.Sockaddr) Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &SCTPAddr{sa.Addr[0:], sa.Port}
	case *syscall.SockaddrInet6:
		return &SCTPAddr{sa.Addr[0:], sa.Port}
	default:
		if sa != nil {
			// Diagnose when we will turn a non-nil sockaddr into a nil.
			panic("unexpected type in sockaddrToSCTP")
		}
	}
	return nil
}

// ResolveSCTPAddr parses addr as a SCTP address of the form
// host:port and resolves domain names or port names to
// numeric addresses on the network net, which must be "sctp",
// "sctp4" or "sctp6".  A literal IPv6 host address must be
// enclosed in square brackets, as in "[::]:80".
func ResolveSCTPAddr(net, addr string) (*SCTPAddr, error) {
	ip, port, err := hostPortToIP(net, addr)
	if err != nil {
		return nil, err
	}
	return &SCTPAddr{ip, port}, nil
}

func (c *SCTPConn) ReadFromSCTP(b []byte) (n int, addr *SCTPAddr, err error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
  var rinfo *syscall.SCTPRcvInfo
	n, sa, rinfo, err := c.fd.ReadFromSCTP(b)
  c.stream = rinfo.Sid

	if err != nil {
		return 0, nil, err
	}
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &SCTPAddr{sa.Addr[0:], sa.Port}
	case *syscall.SockaddrInet6:
		addr = &SCTPAddr{sa.Addr[0:], sa.Port}
	}
	return
}

func (c *SCTPConn) ReadFrom(b []byte) (n int, addr Addr, err error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, uaddr, err := c.ReadFromSCTP(b)
	if err != nil {
		return 0, nil, err
	}
	return n, uaddr.toAddr(), err

}

// TODO
func (c *SCTPConn) WriteTo(b []byte, addr Addr) (n int, err error) {
  println("todo")
  return 0, nil
}

func (c *SCTPConn) SetInitMsg() (err error){
	if !c.ok() {
		return syscall.EINVAL
	}
  var sim syscall.SCTPInitMsg
  sim.Num_ostreams = 100;
  sim.Max_instreams = 100;
  sim.Max_attempts = 0;
  sim.Max_init_timeo = 0;

	return setSCTPInitMsg(c.fd, &sim)
}

func (c *SCTPConn) SetNoDelaySCTP(noDelay bool) error {
  if !c.ok() {
    return syscall.EINVAL
  }
  return setNoDelaySCTP(c.fd, noDelay)
}

func (c *SCTPConn) SetRecvInfo(recvInfo bool) error {
  if !c.ok() {
    return syscall.EINVAL
  }
  return setRecvInfo(c.fd, recvInfo)
}

func setRecvInfo(fd *netFD, recvInfo bool) error {
  if err := fd.incref(false); err != nil {
    return err
  }
  defer fd.decref()
  return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.sysfd, syscall.IPPROTO_SCTP, syscall.SCTP_RECVRCVINFO, boolint(recvInfo)))
}


