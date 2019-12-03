Windows
=======

.. c:function:: void pt_windows_process_init(struct pt_process *proc)

This function initializes a previously allocated 'proc' object.

.. c:function:: int pt_windows_process_attach(struct pt_process *proc, pt_pid_t pid)

This function attemps to attach to the process identified by 'pid' and will
update the pt_process descriptor accordingly.

Internally this function will process Windows debug events to update the
pt_process context until the system breakpoint is encountered.  When this
happens control is returned to the caller.

.. c:function:: void pt_windows_process_detach(struct pt_process *proc)

This function marks the process described by proc for detaching.  Detaching is
not performed immediately, as this function can be called from the context of
debug event handlers.  Real detaching is done from within the debug event pump
loop when it encounters a process marked for detaching.

.. c:function:: ssize_t pt_windows_process_read(struct pt_process *proc, void *dest, const void *src, size_t len)

Reads len bytes of memory from location src in the process described by proc
and place the result into dest.

.. c:function:: ssize_t pt_windows_process_write(struct pt_process *proc, void *dest, const void *src, size_t len)

Writes len bytes of data from src into the memory address dest of the process
described by proc.
