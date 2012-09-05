// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "runtime.h"
#include "arch_GOARCH.h"
#include "stack.h"

// Code related to defer, panic and recover.

uint32 runtime·panicking;
static Lock paniclk;

// Create a new deferred function fn with siz bytes of arguments.
// The compiler turns a defer statement into a call to this.
// Cannot split the stack because it assumes that the arguments
// are available sequentially after &fn; they would not be
// copied if a stack split occurred.  It's OK for this to call
// functions that split the stack.
#pragma textflag 7
uintptr
runtime·deferproc(int32 siz, byte* fn, ...)
{
	Defer *d;
	int32 mallocsiz;

	mallocsiz = sizeof(*d);
	if(siz > sizeof(d->args))
		mallocsiz += siz - sizeof(d->args);
	d = runtime·malloc(mallocsiz);
	d->fn = fn;
	d->siz = siz;
	d->pc = runtime·getcallerpc(&siz);
	if(thechar == '5')
		d->argp = (byte*)(&fn+2);  // skip caller's saved link register
	else
		d->argp = (byte*)(&fn+1);
	runtime·memmove(d->args, d->argp, d->siz);

	d->link = g->defer;
	g->defer = d;

	// deferproc returns 0 normally.
	// a deferred func that stops a panic
	// makes the deferproc return 1.
	// the code the compiler generates always
	// checks the return value and jumps to the
	// end of the function if deferproc returns != 0.
	return 0;
}

// Run a deferred function if there is one.
// The compiler inserts a call to this at the end of any
// function which calls defer.
// If there is a deferred function, this will call runtime·jmpdefer,
// which will jump to the deferred function such that it appears
// to have been called by the caller of deferreturn at the point
// just before deferreturn was called.  The effect is that deferreturn
// is called again and again until there are no more deferred functions.
// Cannot split the stack because we reuse the caller's frame to
// call the deferred function.
#pragma textflag 7
void
runtime·deferreturn(uintptr arg0)
{
	Defer *d;
	byte *argp, *fn;

	d = g->defer;
	if(d == nil)
		return;
	argp = (byte*)&arg0;
	if(d->argp != argp)
		return;
	runtime·memmove(argp, d->args, d->siz);
	g->defer = d->link;
	fn = d->fn;
	if(!d->nofree)
		runtime·free(d);
	runtime·jmpdefer(fn, argp);
}

// Run all deferred functions for the current goroutine.
static void
rundefer(void)
{
	Defer *d;

	while((d = g->defer) != nil) {
		g->defer = d->link;
		reflect·call(d->fn, (byte*)d->args, d->siz);
		if(!d->nofree)
			runtime·free(d);
	}
}

// Print all currently active panics.  Used when crashing.
static void
printpanics(Panic *p)
{
	if(p->link) {
		printpanics(p->link);
		runtime·printf("\t");
	}
	runtime·printf("panic: ");
	runtime·printany(p->arg);
	if(p->recovered)
		runtime·printf(" [recovered]");
	runtime·printf("\n");
}

static void recovery(G*);

// The implementation of the predeclared function panic.
void
runtime·panic(Eface e)
{
	Defer *d;
	Panic *p;

	p = runtime·mal(sizeof *p);
	p->arg = e;
	p->link = g->panic;
	p->stackbase = (byte*)g->stackbase;
	g->panic = p;

	for(;;) {
		d = g->defer;
		if(d == nil)
			break;
		// take defer off list in case of recursive panic
		g->defer = d->link;
		g->ispanic = true;	// rock for newstack, where reflect.call ends up
		reflect·call(d->fn, (byte*)d->args, d->siz);
		if(p->recovered) {
			g->panic = p->link;
			if(g->panic == nil)	// must be done with signal
				g->sig = 0;
			runtime·free(p);
			// put recovering defer back on list
			// for scheduler to find.
			d->link = g->defer;
			g->defer = d;
			runtime·mcall(recovery);
			runtime·throw("recovery failed"); // mcall should not return
		}
		if(!d->nofree)
			runtime·free(d);
	}

	// ran out of deferred calls - old-school panic now
	runtime·startpanic();
	printpanics(g->panic);
	runtime·dopanic(0);
}

// Unwind the stack after a deferred function calls recover
// after a panic.  Then arrange to continue running as though
// the caller of the deferred function returned normally.
static void
recovery(G *gp)
{
	Defer *d;

	// Rewind gp's stack; we're running on m->g0's stack.
	d = gp->defer;
	gp->defer = d->link;

	// Unwind to the stack frame with d's arguments in it.
	runtime·unwindstack(gp, d->argp);

	// Make the deferproc for this d return again,
	// this time returning 1.  The calling function will
	// jump to the standard return epilogue.
	// The -2*sizeof(uintptr) makes up for the
	// two extra words that are on the stack at
	// each call to deferproc.
	// (The pc we're returning to does pop pop
	// before it tests the return value.)
	// On the arm there are 2 saved LRs mixed in too.
	if(thechar == '5')
		gp->sched.sp = (uintptr)d->argp - 4*sizeof(uintptr);
	else
		gp->sched.sp = (uintptr)d->argp - 2*sizeof(uintptr);
	gp->sched.pc = d->pc;
	if(!d->nofree)
		runtime·free(d);
	runtime·gogo(&gp->sched, 1);
}

// Free stack frames until we hit the last one
// or until we find the one that contains the sp.
void
runtime·unwindstack(G *gp, byte *sp)
{
	Stktop *top;
	byte *stk;

	// Must be called from a different goroutine, usually m->g0.
	if(g == gp)
		runtime·throw("unwindstack on self");

	while((top = (Stktop*)gp->stackbase) != nil && top->stackbase != nil) {
		stk = (byte*)gp->stackguard - StackGuard;
		if(stk <= sp && sp < (byte*)gp->stackbase)
			break;
		gp->stackbase = (uintptr)top->stackbase;
		gp->stackguard = (uintptr)top->stackguard;
		if(top->free != 0)
			runtime·stackfree(stk, top->free);
	}

	if(sp != nil && (sp < (byte*)gp->stackguard - StackGuard || (byte*)gp->stackbase < sp)) {
		runtime·printf("recover: %p not in [%p, %p]\n", sp, gp->stackguard - StackGuard, gp->stackbase);
		runtime·throw("bad unwindstack");
	}
}

// The implementation of the predeclared function recover.
// Cannot split the stack because it needs to reliably
// find the stack segment of its caller.
#pragma textflag 7
void
runtime·recover(byte *argp, Eface ret)
{
	Stktop *top, *oldtop;
	Panic *p;

	// Must be a panic going on.
	if((p = g->panic) == nil || p->recovered)
		goto nomatch;

	// Frame must be at the top of the stack segment,
	// because each deferred call starts a new stack
	// segment as a side effect of using reflect.call.
	// (There has to be some way to remember the
	// variable argument frame size, and the segment
	// code already takes care of that for us, so we
	// reuse it.)
	//
	// As usual closures complicate things: the fp that
	// the closure implementation function claims to have
	// is where the explicit arguments start, after the
	// implicit pointer arguments and PC slot.
	// If we're on the first new segment for a closure,
	// then fp == top - top->args is correct, but if
	// the closure has its own big argument frame and
	// allocated a second segment (see below),
	// the fp is slightly above top - top->args.
	// That condition can't happen normally though
	// (stack pointers go down, not up), so we can accept
	// any fp between top and top - top->args as
	// indicating the top of the segment.
	top = (Stktop*)g->stackbase;
	if(argp < (byte*)top - top->argsize || (byte*)top < argp)
		goto nomatch;

	// The deferred call makes a new segment big enough
	// for the argument frame but not necessarily big
	// enough for the function's local frame (size unknown
	// at the time of the call), so the function might have
	// made its own segment immediately.  If that's the
	// case, back top up to the older one, the one that
	// reflect.call would have made for the panic.
	//
	// The fp comparison here checks that the argument
	// frame that was copied during the split (the top->args
	// bytes above top->fp) abuts the old top of stack.
	// This is a correct test for both closure and non-closure code.
	oldtop = (Stktop*)top->stackbase;
	if(oldtop != nil && top->argp == (byte*)oldtop - top->argsize)
		top = oldtop;

	// Now we have the segment that was created to
	// run this call.  It must have been marked as a panic segment.
	if(!top->panic)
		goto nomatch;

	// Okay, this is the top frame of a deferred call
	// in response to a panic.  It can see the panic argument.
	p->recovered = 1;
	ret = p->arg;
	FLUSH(&ret);
	return;

nomatch:
	ret.type = nil;
	ret.data = nil;
	FLUSH(&ret);
}

void
runtime·startpanic(void)
{
	if(m->dying) {
		runtime·printf("panic during panic\n");
		runtime·exit(3);
	}
	m->dying = 1;
	runtime·xadd(&runtime·panicking, 1);
	runtime·lock(&paniclk);
}

void
runtime·dopanic(int32 unused)
{
	static bool didothers;

	if(g->sig != 0)
		runtime·printf("[signal %x code=%p addr=%p pc=%p]\n",
			g->sig, g->sigcode0, g->sigcode1, g->sigpc);

	if(runtime·gotraceback()){
		if(g != m->g0) {
			runtime·printf("\n");
			runtime·goroutineheader(g);
			runtime·traceback(runtime·getcallerpc(&unused), runtime·getcallersp(&unused), 0, g);
		}
		if(!didothers) {
			didothers = true;
			runtime·tracebackothers(g);
		}
	}
	runtime·unlock(&paniclk);
	if(runtime·xadd(&runtime·panicking, -1) != 0) {
		// Some other m is panicking too.
		// Let it print what it needs to print.
		// Wait forever without chewing up cpu.
		// It will exit when it's done.
		static Lock deadlock;
		runtime·lock(&deadlock);
		runtime·lock(&deadlock);
	}

	runtime·exit(2);
}

void
runtime·panicindex(void)
{
	runtime·panicstring("index out of range");
}

void
runtime·panicslice(void)
{
	runtime·panicstring("slice bounds out of range");
}

void
runtime·throwreturn(void)
{
	// can only happen if compiler is broken
	runtime·throw("no return at end of a typed function - compiler is broken");
}

void
runtime·throwinit(void)
{
	// can only happen with linker skew
	runtime·throw("recursive call during initialization - linker skew");
}

void
runtime·throw(int8 *s)
{
	runtime·startpanic();
	runtime·printf("throw: %s\n", s);
	runtime·dopanic(0);
	*(int32*)0 = 0;	// not reached
	runtime·exit(1);	// even more not reached
}

void
runtime·panicstring(int8 *s)
{
	Eface err;

	if(m->gcing) {
		runtime·printf("panic: %s\n", s);
		runtime·throw("panic during gc");
	}
	runtime·newErrorString(runtime·gostringnocopy((byte*)s), &err);
	runtime·panic(err);
}

void
runtime·Goexit(void)
{
	rundefer();
	runtime·goexit();
}
