ptrace -- Process tracing framework
===================================

.. py:module:: ptrace

The ptrace module provides a separate namespace for the Python framework.

.. py:function:: attach(pid)

   Attach to an existing process with the framework.

   :param pid: The PID of the process to attach to.
   :type pid: integer
   :returns: A descriptor for the process attached to.
   :type: ptrace.process or None

   >>> import ptrace
   >>>
   >>> print ptrace.attach(42)               # Assume PID 42 exists and we can attach to it.
   <ptrace.process object at 0x01303980>

.. py:function:: execl(pathname, *argv)

   Execute an executable for use with the framework.

   :param pathname: Pathname of the executable to run.
   :param argv: The command line arguments to pass to the executable.
   :type pathname: string
   :type argv: a variable number of strings, or None
   :returns: A descriptor for the executed process.
   :type: ptrace.process or None

   The execl function executes the executable at pathname with command line
   arguments specified by argv for use with the ptrace framework.

   When argv is omitted, the behaviour depends on the underlying architecture.
   Typically, argv[0] is taken as the program name of the executable.  Some
   platforms, such as Linux and Windows, allow an executable to be ran without
   a program name, while others might not.

   >>> import ptrace
   >>>
   >>> print ptrace.execl("C:\\Windows\\notepad.exe", "notepad")
   <ptrace.process object at 0x01213980>

.. py:function:: log_hook_add(log_hook)

   :param log_hook: A :py:mod:`ptrace.log_hook` object describing the callback.

   Register a log callback function with the framework.  This callback is
   described by the :py:mod:`ptrace.log_hook` object.  All registered log
   callback functions will be invoked when internal log messages are generated
   by the framework.  It is mainly used for generating debug traces of the
   framework itself.

.. py:function:: log_hook_del(log_hook)

   :param log_hook: A :py:class:`ptrace.log_hook` object describing the callback.

   Deregister a log callback function with the framework.  This callback is
   described by the :py:class:`ptrace.log_hook` object.

.. py:function:: main()
   
   Run the main event loop.

.. py:function:: quit()

   Terminate the main event loop.

process objects
---------------

The :py:class:`ptrace.process` class describes a process.

.. py:class:: process()

   .. py:attribute:: id

      Read-only. The process identifier for this process.

      >>> import ptrace
      >>>
      >>> p = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> print "PID:", p.id
      PID: 3380

   .. py:attribute:: modules

      :type: :py:class:`ptrace.module`

      Read-only.  The modules loaded by this process.

      >>> import ptrace
      >>>
      >>> p = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> for module in p.modules:
      >>>     print "0x%.8x %s" % (module.base, module.name)
      ...
      0x74b50000 version
      0x00100000 notepad

   .. py:attribute:: threads

      Read-only.  The threads in this process.

      >>> import ptrace
      >>>
      >>> p = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> print [thread.id for thread in p.threads]
      [1996]

   .. py:method:: breakpoint_set(breakpoint)

      Set a breakpoint on the current process.  This breakpoint can be
      triggered by every thread running in this process.

      :param breakpoint: The :py:class:`ptrace.breakpoint` object describing the breakpoint.
      :type breakpoint: :py:class:`ptrace.breakpoint`

   .. py:method:: breakpoint_unset

   .. py:method:: export_find

   .. py:method:: read(address, size)

      Reads data from the memory image of this process.

      :param address: The address to read data from.
      :param size: The number of bytes to read.
      :returns: The data read or None.
      :type: string

      >>> import ptrace
      >>>
      >>> p    = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> data = p.read(p.threads[0].registers['eip'], 1)
      >>> print data.encode("hex")
      89

   .. py:method:: write(address, data)

      Writes data to the memory image of this process.

      :param address: The address to write data to.
      :param data: The data to write.

thread objects
--------------

The :py:class:`ptrace.thread` class describes a thread.

.. py:class:: thread()

   .. py:attribute:: id

      :type: integer

      Read-only. The process identifier of the thread.

      >>> import ptrace
      >>>
      >>> p = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> print "TID:", p.threads[0].id
      TID: 2140

   .. py:attribute:: process

      :type: :py:class:`ptrace.process`

      The :py:class:`ptrace.process` object this thread belongs to.

   .. py:attribute:: registers

      :type: dict

      The register set of the thread.  The dictionary keys are the register
      names and the values are the register values.

      >>> import ptrace
      >>>
      >>> p = ptrace.execl("C:\\Windows\\notepad.exe")
      >>> print "0x%.8x" % p.threads[0].registers['eip']
      0x7747054f

      .. warning::  This method does not yet provide special purpose registers,
         such as debug registers, FPU registers, and so on.

breakpoint objects
------------------

.. py:function:: ptrace.breakpoint(address, handler)

   The breakpoint class serves as a base class for all types of debug
   breakpoints that can be set on the target process.  Every breakpoint is
   expected to have an address in memory where to break on execution or
   reference, and an associated handler function.

   .. warning:: There may be breakpoints that can be set on conditions that do
      not use an address at all.  We might want to avoid embedding address in
      the base class.

  >>> import ptrace
  >>>
  >>> print ptrace.breakpoint(0xdeadbeef, lambda: None)
  { "address": 0xDEADBEEF, "handler": 0x018C4230 }

breakpoint_sw objects
^^^^^^^^^^^^^^^^^^^^^

The breakpoint_sw object implements software breakpoints.  These are normally
implemented by rewriting the memory image of a process with an architecture
dependent break instruction, and handling the trap that occurs when a thread in
that process executes this instruction.

.. py:class:: breakpoint_sw(address, handler)

   :param address: The address of this breakpoint.  It can be an integer
                   specifying a memory location, or a string specifying a
                   symbol.
   :type address: integer or string
   :param handler: The callback function invoked when the breakpoint is hit.
   :type handler: function

   .. warning:: Symbolic breakpoints are resolved only through the exports table.

The example below executes the notepad.exe application under the ptrace
framework using :py:func:`ptrace.execl`, creates and sets a software breakpoint
on the RtlAllocateHeap function using alloc as a callback event handler.  The
main loop is invoked to start the framework.  The callback handler parses the
arguments to the function according to the calling convention and a format
string describing the structure of the function arguments.  Finally, the result
is printed.

>>> import ptrace
>>>
>>> def alloc(breakpoint, thread):
>>>     (heap, flags, size) = ptrace.cconv.args_get(thread, "%p%lu%zu")
>>>     print "RtlAllocateHeap(0x%x, 0x%x, 0x%x)" % (heap, flags, size)
>>>
>>> p  = ptrace.execl("C:\\Windows\\notepad.exe")
>>> bp = ptrace.breakpoint_sw("ntdll!RtlAllocateHeap", alloc)
>>> p.breakpoint_set(bp)
>>> ptrace.main()

module objects
--------------

The :py:class:`ptrace.module` class describes a module, such as a DLL, DSO, or
an executable image.

.. py:class:: module()

   .. py:attribute:: base

     The load base of the module.

   .. py:attribute:: exports

     The exported function in the module.

   .. py:attribute:: name

     The name of the module.

   .. py:attribute:: pathname

      The pathname of the module.

   .. py:method:: export_find(symbol)

      Finds symbol in the export table of the module.

      :param symbol: The symbol name to find in the module exports.
      :type symbol: string
      :returns: The address of the symbol or None
      :type: integer or None

log_hook objects
----------------

The :py:class:`ptrace.log_hook` class describes internal log callback hooks.

.. py:class:: log_hook(handler, cookie = None)

   .. py:attribute:: handler

      The handler function for this log hook.

   .. py:attribute:: cookie

      The object passed to the handler function for this log hook.

.. toctree::
   :maxdepth: 2
