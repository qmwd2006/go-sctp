// Copyright 2010 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#define SIG_DFL ((void*)0)
#define SIG_IGN ((void*)1)

#define SIG_BLOCK 1
#define SIG_UNBLOCK 2
#define SIG_SETMASK 3

struct sigaction;

void	runtime·raisesigpipe(void);
void	runtime·setsig(int32, void(*)(int32, Siginfo*, void*, G*), bool);
void	runtime·sighandler(int32 sig, Siginfo *info, void *context, G *gp);
void	runtime·sigpanic(void);

void	runtime·setitimer(int32, Itimerval*, Itimerval*);
void	runtime·sigaction(int32, struct sigaction*, struct sigaction*);
void	runtime·sigaltstack(Sigaltstack*, Sigaltstack*);
void	runtime·sigprocmask(int32, Sigset*, Sigset*);
int32	runtime·sysctl(uint32*, uint32, byte*, uintptr*, byte*, uintptr);

#define	NSIG 33
#define	SI_USER	0
