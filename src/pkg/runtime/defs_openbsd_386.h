// Created by cgo -cdefs - DO NOT EDIT
// cgo -cdefs defs_openbsd.go


enum {
	PROT_NONE	= 0x0,
	PROT_READ	= 0x1,
	PROT_WRITE	= 0x2,
	PROT_EXEC	= 0x4,

	MAP_ANON	= 0x1000,
	MAP_PRIVATE	= 0x2,
	MAP_FIXED	= 0x10,

	SA_SIGINFO	= 0x40,
	SA_RESTART	= 0x2,
	SA_ONSTACK	= 0x1,

	EINTR	= 0x4,

	SIGHUP		= 0x1,
	SIGINT		= 0x2,
	SIGQUIT		= 0x3,
	SIGILL		= 0x4,
	SIGTRAP		= 0x5,
	SIGABRT		= 0x6,
	SIGEMT		= 0x7,
	SIGFPE		= 0x8,
	SIGKILL		= 0x9,
	SIGBUS		= 0xa,
	SIGSEGV		= 0xb,
	SIGSYS		= 0xc,
	SIGPIPE		= 0xd,
	SIGALRM		= 0xe,
	SIGTERM		= 0xf,
	SIGURG		= 0x10,
	SIGSTOP		= 0x11,
	SIGTSTP		= 0x12,
	SIGCONT		= 0x13,
	SIGCHLD		= 0x14,
	SIGTTIN		= 0x15,
	SIGTTOU		= 0x16,
	SIGIO		= 0x17,
	SIGXCPU		= 0x18,
	SIGXFSZ		= 0x19,
	SIGVTALRM	= 0x1a,
	SIGPROF		= 0x1b,
	SIGWINCH	= 0x1c,
	SIGINFO		= 0x1d,
	SIGUSR1		= 0x1e,
	SIGUSR2		= 0x1f,

	FPE_INTDIV	= 0x1,
	FPE_INTOVF	= 0x2,
	FPE_FLTDIV	= 0x3,
	FPE_FLTOVF	= 0x4,
	FPE_FLTUND	= 0x5,
	FPE_FLTRES	= 0x6,
	FPE_FLTINV	= 0x7,
	FPE_FLTSUB	= 0x8,

	BUS_ADRALN	= 0x1,
	BUS_ADRERR	= 0x2,
	BUS_OBJERR	= 0x3,

	SEGV_MAPERR	= 0x1,
	SEGV_ACCERR	= 0x2,

	ITIMER_REAL	= 0x0,
	ITIMER_VIRTUAL	= 0x1,
	ITIMER_PROF	= 0x2,
};

typedef struct Tfork Tfork;
typedef struct Sigaltstack Sigaltstack;
typedef struct Sigcontext Sigcontext;
typedef struct Siginfo Siginfo;
typedef struct StackT StackT;
typedef struct Timespec Timespec;
typedef struct Timeval Timeval;
typedef struct Itimerval Itimerval;

#pragma pack on

struct Tfork {
	byte	*tf_tcb;
	int32	*tf_tid;
	int32	tf_flags;
};

struct Sigaltstack {
	byte	*ss_sp;
	uint32	ss_size;
	int32	ss_flags;
};
struct Sigcontext {
	int32	sc_gs;
	int32	sc_fs;
	int32	sc_es;
	int32	sc_ds;
	int32	sc_edi;
	int32	sc_esi;
	int32	sc_ebp;
	int32	sc_ebx;
	int32	sc_edx;
	int32	sc_ecx;
	int32	sc_eax;
	int32	sc_eip;
	int32	sc_cs;
	int32	sc_eflags;
	int32	sc_esp;
	int32	sc_ss;
	int32	sc_onstack;
	int32	sc_mask;
	int32	sc_trapno;
	int32	sc_err;
	void	*sc_fpstate;
};
struct Siginfo {
	int32	si_signo;
	int32	si_code;
	int32	si_errno;
	byte	_data[116];
};
typedef	uint32	Sigset;
typedef	byte	Sigval[4];

struct StackT {
	byte	*ss_sp;
	uint32	ss_size;
	int32	ss_flags;
};

struct Timespec {
	int32	tv_sec;
	int32	tv_nsec;
};
struct Timeval {
	int32	tv_sec;
	int32	tv_usec;
};
struct Itimerval {
	Timeval	it_interval;
	Timeval	it_value;
};


#pragma pack off
