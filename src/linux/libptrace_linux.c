/* libptrace, a process tracing and manipulation library.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Copyright (C) 2006-2019 Ronald Huizer <rhuizer@hexpedition.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1 as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * version 2.1 for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 2.1 along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
 * AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
 * DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
 * OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
 * WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
 * EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
 * THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
 * CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
 * EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
 * OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
 * PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
 * REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
 * UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
 *
 * libptrace_linux.c
 *
 * Author: Ronald Huizer <rhuizer@hexpedition.com>
 *
 */
#include <config.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <libptrace.h>
#include <libptrace_wrapper.h>

static int syscall_trap = SIGTRAP;

int ptrace_open(struct ptrace_context *p, ptrace_pid_t tid)
{
	return ptrace_attach(p, tid);
}

/* Open a process / thread given its identifier */
/* Linux signal delivery on traced threads:
 *
 * 1/ When the thread is trace-suspended, signal delivery is deferred
 *    until the process runs again with PTRACE_CONT, PTRACE_DETACH or
 *    the single stepping functions.
 * 2/ When the thread is running and traced, signal delivery is notified
 *    to the parent through wait() events.  It is then up to the parent to
 *    delegate the signal to the child.
 * 3/ Part of the SIGCONT/SIGSTOP logic is handled at signal dispatch time
 *    rather than delivery time.
 *    SIGSTOP removes pending SIGCONT signals from the queue, and its
 *    handler invocation suspends a child.
 *    SIGCONT removed pending SIGSTOP signals from the queue, and
 *    immediatly resumed child execution in case its suspended.
 */
int ptrace_attach(struct ptrace_context *p, ptrace_pid_t tid)
{
	int signal;
	int ret;

	/* Initialize the part of the ptrace library context which we might
	 * use it in this function.
	 */
	p->tid = tid;
	p->flags = 0;
	PTRACE_ERR_CLEAR(p);

	if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	/* Check if the process was stopped already.  Note that the
	 * SIGSTOP sent by PTRACE_ATTACH should result in a different
	 * state in /proc/pid/status than a regular stop, so we can
	 * differentiate.
	 *
	 * This works because the first SIGSTOP delivered to a thread
	 * after PTRACE_ATTACH transitions the thread to 'trace
	 * suspended' state.  So, if we find a regular 'suspended' state
	 * here, the thread must have been suspended before PTRACE_ATTACH.
	 */
	if ( (ret = ptrace_procfs_status_is_stopped(tid)) == -1)
		goto out_detach_error;

	/* Process was suspended.  We want to migrate it from the regular
	 * suspended state, to a trace suspended state.  We do this by
	 * sending SIGCONT, which resumes the target process immediatly,
	 * whether it is traced or not.  After resumption the delivery of
	 * SIGCONT then triggers a tracing stop.
	 * This works even when the tracee is stormed with SIGSTOPs due to
	 * the handling below.
	 */
	if (ret == 1) {
		if (ptrace_signal_send(p, SIGCONT) == -1)
			goto out_detach_error;
		p->flags |= PTRACE_FLAG_SUSPENDED;
	}

	/* Now we can wait() for SIGSTOP without any problems.  It should
	 * arrive even if the process was already suspended.
	 *
	 * There is a theoretical race-condition here: SIGSTOP suspends a
	 * target process in the signal handler part of the target, which
	 * is invoked when the target is scheduled.
	 *
	 * SIGCONT continues a process and clears SIGSTOP from the pending
	 * signal queue on signal dispatch.
	 *
	 * If SIGSTOP is queued when a SIGCONT arrives, SIGSTOP will be
	 * cleared from the queue, and we would hang forever.  However,
	 * the SIGCONT would also suspend the process, as its already
	 * traced, so we wait for both SIGSTOP *and* SIGCONT events.
	 *
	 * Love the ptrace API design... Really...
	 */
	do {
		switch(signal = ptrace_wait_event(p)) {
		case -1:
			goto out_detach;
		case SIGCONT:
		case SIGSTOP:
			break;
		default:
			if (ptrace_continue_signal(p, signal) == -1)
				goto out_detach;
		}
	} while (signal != SIGSTOP && signal != SIGCONT);

#ifdef PTRACE_O_TRACESYSGOOD
	/* ptrace singlestep/syscall etc. will now cause the child to signal
	 * SIGTRAP orred with 0x80, to distinguish from real SIGTRAPs.
	 */
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == 0)
		syscall_trap |= 0x80;
#endif

	/* Initialize the current altstack as the original stack. */
	p->stack.flags = PTRACE_ALTSTACK_ORIG;

#ifdef __x86_64__
	/* If on x86-64 we check whether the process is running native, or
	 * in emulated 32-bit mode.
	 * Error can only be internal and has been set by the function.
	 */
	if (ptrace_x86_64_update_compat32_mode(p) == -1)
		goto out_detach;
#endif

	return 0;

out_detach_error:
	PTRACE_ERR_SET_EXTERNAL(p);
out_detach:
	/* Try to detach; if this fails it should be because of ESRCH
	 * and we ignore the return value to make things less confusing.
	 */
	ptrace(PTRACE_DETACH, tid, NULL, NULL);
	return -1;
}

int ptrace_close(struct ptrace_context *p)
{
	return ptrace_detach(p);
}

/* Close the traced process given its context */
int ptrace_detach(struct ptrace_context *p)
{
	void *data = NULL;

	/* If the process was suspended when we attached to it, we suspend
	 * it again.
	 *
	 * XXX: handle the case where we get SIGCONT while libptrace is
	 * attached.
	 */
	if (p->flags & PTRACE_FLAG_SUSPENDED) {

		/* Before we can detach, the LWP should be stopped. */
		if (kill(p->tid, SIGSTOP) == -1) {
			PTRACE_ERR_SET_EXTERNAL(p);
			return -1;
		}
		data = (void *)SIGSTOP;
	}

	if (ptrace(PTRACE_DETACH, p->tid, NULL, data) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

int ptrace_execve(struct ptrace_context *p, const char *filename,
                  char *const argv[], char *const envp[])
{
	/* Initialize the part of the ptrace library context which we might
	 * use it in this function.
	 */
	p->flags = 0;
	PTRACE_ERR_CLEAR(p);

	switch (p->tid = fork()) {
	case -1:
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	case 0:	/* child */
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
			/* XXX: should notify parent */
			PTRACE_ERR_SET_EXTERNAL(p);
			exit(EXIT_FAILURE);
		}

		execve(filename, argv, envp);
		exit(EXIT_FAILURE);
	}

	/* Child delivers SIGTRAP on execve() -- synchronise on it. */
	if (ptrace_wait_signal(p, SIGTRAP) == -1)
		goto out_detach;

#ifdef PTRACE_O_TRACESYSGOOD
	/* ptrace singlestep/syscall etc. will now cause the child to signal
	 * SIGTRAP orred with 0x80, to distinguish from real SIGTRAPs.
	 */
	if (ptrace(PTRACE_SETOPTIONS, p->tid, NULL, PTRACE_O_TRACESYSGOOD) == 0)
		syscall_trap |= 0x80;
#endif

	/* Initialize the current altstack as the original stack. */
	p->stack.flags = PTRACE_ALTSTACK_ORIG;

#ifdef __x86_64__
	/* If on x86-64 we check whether the process is running native, or
	 * in emulated 32-bit mode.
	 * Error can only be internal and has been set by the function.
	 */
	if (ptrace_x86_64_update_compat32_mode(p) == -1)
		goto out_detach;
#endif

	return 0;

out_detach:
	/* Try to detach; if this fails it should be because of ESRCH
	 * and we ignore the return value to make things less confusing.
	 */
	ptrace(PTRACE_DETACH, p->tid, NULL, NULL);
	return -1;
}

/* Write 'len' bytes from 'src' to the location 'dest' in the process described
 * in the ptrace_context 'p'.
 *
 * XXX: API might not conform to Windows stuff. If we have an error half-way,
 * then we'll have written stuff already. Does WriteProcessMemory test VM area
 * first?
 *
 * XXX: align reads/writes? Not too useful maybe, ptrace syscall overhead much
 * worse..
 */
int ptrace_write(struct ptrace_context *p, void *dest, const void *src, size_t len)
{
	size_t rem = len % sizeof(void *);
	size_t quot = len / sizeof(void *);
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	assert(sizeof(void *) == sizeof(long));

	while (quot-- != 0) {
		if ( ptrace(PTRACE_POKEDATA, p->tid, d, *(void **)s) == -1 )
			goto out_error;
		s += sizeof(void *);
		d += sizeof(void *);
	}

	/* We handle the last unpadded value here.
	 *
	 * Suppose we have the situation where we have written the string
	 * "ABCD" to 'dest', still want to write to the byte at *, but have an
	 * unadressable page at X. We'll find the ptrace write at 'X' returns
	 * an error, and will need to start writing at 'B' to satisfy this
	 * request.
	 *
	 * +---+---+---+---+---+---+
	 * | A | B | C | D | * | X |
	 * +---+---+---+---+---+---+
	 *
	 * This situation is handled in the code below, which is why it might
	 * look confusing.
	 */
	if (rem != 0) {
		long w;
		unsigned char *wp = (unsigned char *)&w;

		w = ptrace(PTRACE_PEEKDATA, p->tid, d, NULL);
		if (w == -1 && errno != 0) {
			d -= sizeof(void *) - rem;

			w = ptrace(PTRACE_PEEKDATA, p->tid, d, NULL);
			if (w == -1 && errno != 0)
				goto out_error;

			wp += sizeof(void *) - rem;
		}

		while (rem-- != 0)
			wp[rem] = s[rem];

		if (ptrace(PTRACE_POKEDATA, p->tid, d, w) == -1)
			goto out_error;
	}

	return 0;

out_error:
	PTRACE_ERR_SET_EXTERNAL(p);
	return -1;
}

/* Read 'len' bytes from 'src' in the process
 * described in the ptrace_context 'p' to the location 'dest'.
 */
int ptrace_read(struct ptrace_context *p, void *dest, const void *src, size_t len)
{
	long w;
	size_t rem = len % sizeof(void *);
	size_t quot = len / sizeof(void *);
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	assert(sizeof(void *) == sizeof(long));

	while (quot-- != 0) {
		w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
		if (w == -1 && errno != 0)
			goto out_error;

		*((long *)d) = w;

		s += sizeof(long);
		d += sizeof(long);
	}

	/* The remainder of data to read will be handled in a manner
	 * analogous to ptrace_write().
	 */
	if (rem != 0) {
		long w;
		unsigned char *wp = (unsigned char *)&w;

		w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
		if (w == -1 && errno != 0) {
			s -= sizeof(long) - rem;

			w = ptrace(PTRACE_PEEKDATA, p->tid, s, NULL);
			if (w == -1 && errno != 0)
				goto out_error;

			wp += sizeof(void *) - rem;
		}

		while (rem-- != 0)
			d[rem] = wp[rem];
	}

	return 0;

out_error:
	PTRACE_ERR_SET_EXTERNAL(p);
	return -1;
}

const char *ptrace_errmsg(struct ptrace_context *p)
{
	if (p->error.flags & PTRACE_ERR_FLAG_EXTERNAL) {
		strncpy(p->error.errmsg, strerror(p->error.external),
		        sizeof(p->error.errmsg));
		p->error.errmsg[sizeof(p->error.errmsg) - 1] = 0;
	}
	
	return p->error.errmsg;
}

int ptrace_perror(struct ptrace_context *pctx, const char *s)
{
	if (s != NULL && *s != 0)
		return fprintf(stderr, "%s: %s\n", s, ptrace_errmsg(pctx));

	return fprintf(stderr, "%s\n", ptrace_errmsg(pctx));
}

int ptrace_continue(struct ptrace_context *pctx)
{
	if (ptrace(PTRACE_CONT, pctx->tid, NULL, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

int ptrace_continue_signal(struct ptrace_context *pctx, int signum)
{
	unsigned long __signum = (unsigned long)signum;

	if (ptrace(PTRACE_CONT, pctx->tid, NULL, (void *)__signum) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

int ptrace_signal_send(struct ptrace_context *pctx, int signal)
{
	if (syscall(__NR_tkill, pctx->tid, signal) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

/* Stop the process we're currently tracing.
 * On linux we do this by sending SIGSTOP, and then resuming the target
 * process.  This allows the function to be used consistently in several
 * locations, and will not queue SIGSTOP in case we're already suspended.
 */
int ptrace_stop(struct ptrace_context *pctx)
{
	/* We cannot use PTRACE_CONT to deliver SIGSTOP, so we send the
	 * SIGSTOP signal directly to the LWP, and resume it -- signal
	 * delivery triggers on process scheduling, so the suspend should
	 * be immediate.
	 */
	if (ptrace_signal_send(pctx, SIGSTOP) == -1)
		return -1;

	if (ptrace_continue(pctx) == -1)
		return -1;

	return 0;
}

int ptrace_wait_breakpoint(struct ptrace_context *pctx)
{
	return ptrace_wait_signal(pctx, SIGTRAP);
}

/* Continue running the remote process until we receive a signal of signum.
 */
int ptrace_wait_signal(struct ptrace_context *pctx, int signum)
{
	int status;

	do {
		if (waitpid_no_EINTR(pctx->tid, &status, 0) == -1) {
			PTRACE_ERR_SET_EXTERNAL(pctx);
			return -1;
		}

		/* Child terminated normally */
		if (WIFEXITED(status)) {
			PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
			return -1;
		}

		/* Child was terminated by a signal */
		if (WIFSIGNALED(status)) {
			PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
			return -1;
		}

		/* The child was stopped by a signal; this is what we
		 * expected.  If it is not the signal we're looking for,
		 * delegate it to the child and continue.
		 */
		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == SIGCONT)
				pctx->flags &= ~PTRACE_FLAG_SUSPENDED;

			if (WSTOPSIG(status) != signum &&
			    ptrace_continue_signal(pctx, WSTOPSIG(status)) == -1)
				return -1;
		}
	} while (!WIFSTOPPED(status) || WSTOPSIG(status) != signum);

	return 0;
}

int ptrace_wait_event(struct ptrace_context *pctx)
{
	int status;

	if (waitpid_no_EINTR(pctx->tid, &status, 0) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	/* Child terminated normally */
	if (WIFEXITED(status)) {
		PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
		return -1;
	}

	/* Child was terminated by a signal */
	if (WIFSIGNALED(status)) {
		PTRACE_ERR_SET_INTERNAL(pctx, PTRACE_ERR_EXITED);
		return -1;
	}

	/* The child was stopped by a signal; this is what we
	 * expected.  If it is not the signal we're looking for,
	 * delegate it to the child and continue.
	 */
	if (WIFSTOPPED(status))
		return WSTOPSIG(status);

	return 0;
}


void *ptrace_malloc(struct ptrace_context *p, size_t size)
{
	void *ret;

	if (size == 0)
		size = 1;

	ret = ptrace_mmap(p, (void *) 0, size + sizeof(size_t),
	                  PROT_READ | PROT_WRITE | PROT_EXEC,
			  MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if (ret == MAP_FAILED)
		return NULL;

	if (ptrace_write(p, ret, &size, sizeof(size_t)) == -1) {
		/* XXX: double fault */
		ptrace_munmap(p, ret, size + sizeof(size_t));
		return NULL;
	}

	return ret + sizeof(size_t);
}

int ptrace_free(struct ptrace_context *p, void *ptr)
{
	size_t size;

	if (ptr == NULL)
		return 0;
	
	ptr -= sizeof(size_t);
	if ( ptrace_read(p, &size, ptr, sizeof(size_t)) == -1 )
		return -1;

	return ptrace_munmap(p, ptr, size + sizeof(size_t));
}

int ptrace_get_pagesize(struct ptrace_context *p, int *page_size)
{
	long __page_size;

	errno = 0;
	__page_size = sysconf(_SC_PAGESIZE);
	if (__page_size == -1 && errno == EINVAL) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	*page_size = (int)__page_size;

	return 0;
}

int ptrace_option_set_trace_syscall(struct ptrace_context *pctx)
{
	return -1;
}
