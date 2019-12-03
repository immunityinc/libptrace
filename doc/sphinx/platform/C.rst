C framework
===========

The C framework is composed of several modules.  The most low-level ones are
the the native components, which implement debugging functionality on a
specific platform, and also offers non-portable functionality only available on
that platform.  The native components offer the fastest debugging
implementation, at the cost of abstraction and portability.  A system can have
multiple native components available, such as both a 32-bit WoW and 64-bit
component on Windows.

Intermediate components offer a portable interface over the native components.
They abstract away most of the native components, but still assume development
and compile time knowledge about the underlying architecture.  These components
still offer a high amount of speed, and an API that does not carry abstraction
to extremes.  For instance, the developer is still assumed to be aware of the
register sets present on the architecture he is developing for, and as such the
content of the register structure is not opaque.

High-level components offer a portable interface over the intermediate
components and allow for run-time introspection of the target architecture.
For instance, the API can be used to determine the properties of the register
sets on the debuggee system, such as their names, and sizes.  Similarly,
pointers are now abstract objects, and it becomes possible to remotely debug a
system with 64-bit registers from a 32-bit system.
These components are mainly used for remote debugging of a variety of
architectures through a common interface.

.. toctree::
   :maxdepth: 2

   native
