package net

import (
  "io"
  "syscall"
)

func (fd *netFD) ReadFromSCTP(b []byte)  (n int, sa syscall.Sockaddr, rinfo *syscall.SCTPRcvInfo, err error) {
  fd.rio.Lock()
  defer fd.rio.Unlock()
  if err := fd.incref(false); err != nil {
    return 0, nil, rinfo, err
  }
  defer fd.decref()

  //sa, msg, info, flags, err = syscall.SCTPReceiveMessage(fd.sysfd)

  for {
    n, sa, rinfo, _, err = syscall.SCTPReceiveMessage(fd.sysfd, b)
    if err == syscall.EAGAIN {
      err = errTimeout
      if fd.rdeadline >= 0 {
        if err = pollserver.WaitRead(fd); err == nil {
          continue
        }
      }
    }
    if err != nil {
      n = 0
    }
    break
  }
  if err != nil && err != io.EOF {
    err = &OpError{"read", fd.net, fd.laddr, err}
  }
  return
}

