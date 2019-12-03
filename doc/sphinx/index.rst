.. libptrace documentation master file, created by
   sphinx-quickstart on Fri Sep 14 10:57:33 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

libptrace
=========

libptrace is a cross-platform process debugging, manipulation and tracing API.
It abstracts away the platform specific methods of such activities under a
common interface.  It is written in C, but provides higher level Python
bindings.

The aim is to have a consistent interface to debug processes on different
architectures, be it native Windows 7 64-bit debugging, or remote debugging
of an ARM Linux system using RSP as a transport protocol.

.. toctree::
   :maxdepth: 2

   platform/C
   platform/Python
   platform/installer

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
