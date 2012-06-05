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

func (fd *netFD) WriteToSCTP(p []byte, sinfo *syscall.SCTPSndInfo, sa syscall.Sockaddr) (n int, err error) {
  fd.wio.Lock()
	defer fd.wio.Unlock()
	if err := fd.incref(false); err != nil {
		return 0, err
	}
	defer fd.decref()
	for {
		err = syscall.SCTPSendmsg(fd.sysfd, p, sinfo, sa, 0)
		if err == syscall.EAGAIN {
			err = errTimeout
			if fd.wdeadline >= 0 {
				if err = pollserver.WaitWrite(fd); err == nil {
					continue
				}
			}
		}
		break
	}
	if err == nil {
		n = len(p)
	} else {
		err = &OpError{"write", fd.net, fd.raddr, err}
	}
	return

}
