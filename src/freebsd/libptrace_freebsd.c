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
 * libptrace_freebsd.c
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
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <libptrace.h>
#include <libptrace_wrapper.h>

/* signo to /proc/pid/ctl signal name array */
static char *signames[_SIG_MAXSIG + 1] =
{
	[SIGHUP] = "hup",	[SIGINT] = "int",
	[SIGQUIT] = "quit",	[SIGILL] = "ill",
	[SIGTRAP] = "trap",	[SIGABRT] = "abrt",
	[SIGIOT] = "iot",	[SIGEMT] = "emt",
	[SIGFPE] = "fpe",	[SIGKILL] = "kill",
	[SIGBUS] = "bus",	[SIGSEGV] = "segv",
	[SIGSYS] = "sys",	[SIGPIPE] = "pipe",
	[SIGALRM] = "alrm",	[SIGTERM] = "term",
	[SIGURG] = "urg",	[SIGSTOP] = "stop",
	[SIGTSTP] = "tstp",	[SIGCONT] = "cont",
	[SIGCHLD] = "chld",	[SIGTTIN] = "ttin",
	[SIGTTOU] = "ttou",	[SIGIO] = "io",
	[SIGXCPU] = "xcpu",	[SIGXFSZ] = "xfsz",
	[SIGVTALRM] = "vtalrm",	[SIGPROF] = "prof",
	[SIGWINCH] = "winch",	[SIGINFO] = "info",
	[SIGUSR1] = "usr1",	[SIGUSR2] = "usr2"
};

/* Try to initialize FreeBSD tracing and debugging through procfs.
 * This interface is more sane and powerful than ptrace(), so only
 * in case this fails we fall back to using ptrace().
 */
static int __init_procfs(struct ptrace_context *p)
{
	char procfile[128];
	long arg;

	/* Open the procfs based event notification interface. */
	snprintf(procfile, sizeof(procfile), "/proc/%d/mem", p->tid);
	if ( (p->procmemfd = open(procfile, O_RDWR)) == -1)
		return -1;

	/* And the debugger control interface. */
	snprintf(procfile, sizeof(procfile), "/proc/%d/ctl", p->tid);
	if ( (p->procctlfd = open(procfile, O_WRONLY)) == -1)
		goto out_close_mem;

	/* And clear PF_LINGER, so that on the last close of the procmemfd
	 * the process will be resumed.
	 */
	if (ioctl(p->procmemfd, PIOCGFL, &arg) == -1)
		goto out_close;

	arg &= ~PF_LINGER;

	if (ioctl(p->procmemfd, PIOCSFL, &arg) == -1)
		goto out_close;

	/* We will monitor signals through procfs as well. */
	if (ioctl(p->procmemfd, PIOCBIS, S_SIG) == -1)
		goto out_close;

	if (write(p->procctlfd, "attach", 6) != 6)
		goto out_close;

	return 0;

out_close:
	close(p->procctlfd);
	p->procctlfd = -1;
out_close_mem:
	close(p->procmemfd);
	p->procmemfd = -1;
	return -1;
}

int ptrace_open(struct ptrace_context *p, ptrace_pid_t tid)
{
	return ptrace_attach(p, tid);
}

/* Open a process / thread given its identifier */
int ptrace_attach(struct ptrace_context *p, ptrace_pid_t tid)
{
	union ptrace_event event;
	int signo;
	long arg;
	int ret;

	/* Initialize the part of the ptrace library context which we might
	 * use it in this function.
	 */
	p->tid = tid;
	p->flags = 0;
	PTRACE_ERR_CLEAR(p);

	if (__init_procfs(p) == -1) {

	if (ptrace(PT_ATTACH, tid, NULL, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	}

	/* For the rationale behind this loop, see the rant in
	 * libptrace_linux.c
	 */
	do {
		if (ptrace_event_wait(p, &event) == -1 ||
		    event.type != PTRACE_EVENT_SIGNAL)
			goto out_detach;

		signo = event.signal.signo;
		switch(signo) {
		case SIGCONT:
		case SIGSTOP:
			break;
		default:
			if (ptrace_signal_continue(p, signo) == -1)
				goto out_detach;
		}
	} while (signo != SIGSTOP && signo != SIGCONT);

	/* Initialize the current altstack as the original stack. */
	p->stack.flags = PTRACE_ALTSTACK_ORIG;

	return 0;

out_detach_error:
	PTRACE_ERR_SET_EXTERNAL(p);
out_detach:
	/* Try to detach; if this fails it should be because of ESRCH
	 * and we ignore the return value to make things less confusing.
	 */
	ptrace(PT_DETACH, tid, (caddr_t)1, NULL);
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

	/* Detach the debugger */
	if (p->procctlfd != -1) {
		if (write(p->procctlfd, "detach", 6) != 6) {
			PTRACE_ERR_SET_EXTERNAL(p);
			return -1;
		}

		close(p->procctlfd);
	}

	/* If we have a handle to procfs/mem first release it. */
	if (p->procmemfd != -1)
		close(p->procmemfd);

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
		if (ptrace(PT_TRACE_ME, 0, 0, 0) == -1) {
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

	/* Initialize the current altstack as the original stack. */
	p->stack.flags = PTRACE_ALTSTACK_ORIG;

	return 0;

out_detach:
	/* Try to detach; if this fails it should be because of ESRCH
	 * and we ignore the return value to make things less confusing.
	 */
	ptrace(PT_DETACH, p->tid, (caddr_t)1, NULL);
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
		if (ptrace(PT_WRITE_D, p->tid, d, *(void **)s) == -1)
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

		w = ptrace(PT_READ_D, p->tid, d, NULL);
		if (w == -1 && errno != 0) {
			d -= sizeof(void *) - rem;

			w = ptrace(PT_READ_D, p->tid, d, NULL);
			if (w == -1 && errno != 0)
				goto out_error;

			wp += sizeof(void *) - rem;
		}

		while (rem-- != 0)
			wp[rem] = s[rem];

		if (ptrace(PT_WRITE_D, p->tid, d, w) == -1)
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
		w = ptrace(PT_READ_D, p->tid, s, NULL);
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

		w = ptrace(PT_READ_D, p->tid, s, NULL);
		if (w == -1 && errno != 0) {
			s -= sizeof(long) - rem;

			w = ptrace(PT_READ_D, p->tid, s, NULL);
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

/* Generic register access functions
 */
int ptrace_get_registers(struct ptrace_context *p,
                         struct ptrace_registers *regs)
{
	if (ptrace(PT_GETREGS, p->tid, regs, NULL) == -1) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
}

int ptrace_set_registers(struct ptrace_context *p,
                         struct ptrace_registers *regs)
{
	if (ptrace(PT_SETREGS, p->tid, regs, NULL) == -1 ) {
		PTRACE_ERR_SET_EXTERNAL(p);
		return -1;
	}

	return 0;
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
	/* only resume the tracer if we didnt resume it yet */
	if (!(pctx->flags & PTRACE_FLAG_FREEBSD_PIOCCONT) &&
	    ioctl(pctx->procmemfd, PIOCCONT, 0) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	if (write(pctx->procctlfd, "run", 3) != 3) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

int ptrace_signal(struct ptrace_context *pctx, int signum)
{
	ssize_t ret;

	ret = write(pctx->procctlfd,
	            signames[signum], strlen(signames[signum]));
	if (ret == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

/* send a signal to the target process, and have it continue
 * processing it.
 */
int ptrace_signal_continue(struct ptrace_context *pctx, int signum)
{
	union ptrace_event event;
	ssize_t ret;

	if (signum <= 0 || signum > _SIG_MAXSIG) {
		/* XXX: set internal error */
		return -1;
	}

	/* The FreeBSD kernel is a fucked up pile of mammoth dung.
	 *
	 * Signal delivery to a tracee sets up a special signal stop state
	 * called SSTOP, in which the signal can be delivered through either
	 * procfs or ptrace.
	 *
	 * This means that we first send the signal, then wait for it to
	 * trigger an event, and then send it again.  FUCK FUCK FUCK!
	 */
	ret = write(pctx->procctlfd,
	            signames[signum], strlen(signames[signum]));
	if (ret == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	if (ptrace_event_wait(pctx, &event) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	/* Sanity check -- signal event should be first.
	 *
	 * XXX: how about syscall exit when interrupted by
	 * this signal?
	 */
	if (event.type != PTRACE_EVENT_SIGNAL ||
	    event.signal.signo != signum) {
		fprintf(stderr, "Should NOT happen!\n");
		exit(EXIT_FAILURE);
	}

	ret = write(pctx->procctlfd,
	            signames[signum], strlen(signames[signum]));
	if (ret == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	return 0;
}

int ptrace_stop(struct ptrace_context *pctx)
{
	if (ptrace_signal_continue(pctx, SIGSTOP) == -1)
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
			    ptrace_signal_continue(pctx, WSTOPSIG(status)) == -1)
				return -1;
		}
	} while (!WIFSTOPPED(status) || WSTOPSIG(status) != signum);

	return 0;
}

/* Hairy BSD-ism to migrate a pioctl trace stop state to a debugger stop
 * state.  This is because event monitoring is only done through the tracer,
 * but manipulation needs a debugger stop.
 *
 * Note that we do not need to really have the signal delivered to the
 * tracee, in fact, we prefer this not happening.  We just need to trigger a
 * debug stop.
 */
int __ptrace_trace_stop_to_debug_stop(struct ptrace_context *pctx)
{
	union ptrace_event event;

	if (ptrace_signal(pctx, SIGSTOP) == -1)
		return -1;

	if (ioctl(pctx->procmemfd, PIOCCONT, 0) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	if (ptrace_event_wait(pctx, &event) == -1)
		return -1;

	if (event.type != PTRACE_EVENT_SIGNAL ||
	    event.signal.signo != SIGSTOP) {
		fprintf(stderr, "Should NOT happen!\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

/* First of all we consult the tracing events, as this allows us to monitor
 * all events, as opposed to when using ptrace() or /proc/pid/ctl events
 * through waitpid(), which does not provide systemcall entry and exit events.
 *
 * This means our main event loop is driven by the trace part, and not
 * the debugger part of the kernel.
 *
 * For signal events we continue the trace event, which triggers the debugger
 * signal event.  At this point we decide whether to deliver or not.
 *
 * For other events, we have to transform the trace suspended state to a
 * debug suspended state.  This is hairy, but we do it by scheduling a signal,
 * resuming the tracer, and having the debugger catch it. Urk, one more the
 * FreeBSD kernel proves to be the pinnacle of well thought out design.
 */
int ptrace_event_wait(struct ptrace_context *pctx, union ptrace_event *event)
{
	struct procfs_status status;
	int wpstatus;

	if (ioctl(pctx->procmemfd, PIOCWAIT, &status) == -1) {
		PTRACE_ERR_SET_EXTERNAL(pctx);
		return -1;
	}

	/* tracer is in suspended mode */
	pctx->flags &= ~PTRACE_FLAG_FREEBSD_PIOCCONT;

	switch(status.why) {
	case S_SIG:
		event->type = PTRACE_EVENT_SIGNAL;
		event->signal.signo = status.val;

		/* resume, and have the debugger trap the signal */
		if (ioctl(pctx->procmemfd, PIOCCONT, status.val) == -1) {
			PTRACE_ERR_SET_EXTERNAL(pctx);
			return -1;
		}

		/* wait on the debugger to trap it */
		if (waitpid_no_EINTR(pctx->tid, &wpstatus, 0) == -1) {
			PTRACE_ERR_SET_EXTERNAL(pctx);
			return -1;
		}

		/* flag we have already resumed the tracer */
		pctx->flags |= PTRACE_FLAG_FREEBSD_PIOCCONT;
		break;
	case S_SCE:
		if (__ptrace_trace_stop_to_debug_stop(pctx) == -1)
			return -1;

		if (__ptrace_get_eax(pctx, &event->syscall.number) == -1)
			return -1;

		event->type = PTRACE_EVENT_SYSCALL_IN;
		event->syscall.nargs = status.val;
		break;
	case S_SCX:
		if (__ptrace_trace_stop_to_debug_stop(pctx) == -1)
			return -1;

		event->type = PTRACE_EVENT_SYSCALL_OUT;
		event->syscall.nargs = status.val;
		break;
	case S_EXEC:
	case S_CORE:
	case S_EXIT:
		printf("Unimplemented\n");
		exit(EXIT_FAILURE);
	default:
		fprintf(stderr, "Unknown /proc/pid/mem event!");
		exit(EXIT_FAILURE);
	}

	return 0;
}

void *ptrace_malloc(struct ptrace_context *p, size_t size)
{
	void *ret;

	if (size == 0)
		size = 1;

	ret = ptrace_mmap(p, (void *) 0, size + sizeof(size_t),
	                  PROT_READ | PROT_WRITE | PROT_EXEC,
			  MAP_PRIVATE | MAP_ANON, -1, 0);

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
	if (ptrace_read(p, &size, ptr, sizeof(size_t)) == -1)
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
	long arg = S_SIG | S_SCE | S_SCX;

	/* XXX: we can emulate this if we have ptrace but no procfs */
	if (pctx->procmemfd != -1) {
		if (ioctl(pctx->procmemfd, PIOCBIS, arg) == -1) {
			PTRACE_ERR_SET_EXTERNAL(pctx);
			return -1;
		}
	} else {
		return -1;
	}

	return 0;
}
