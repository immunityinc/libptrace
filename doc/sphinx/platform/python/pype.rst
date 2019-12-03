pype -- A Portable Executable processing library
================================================

.. py:module:: pype

The pype module provides Portable Executable ABI handling functionality.  Its
primary development aim was to do away with the idea that such libraries need
to work on files directly.  pype abstracts away filesystem based access such
that it becomes possible to specify other I/O operations to access PE
executables.  This makes it possible to use the library to process PE
executables in memory accessed through a remote debugging interface.

.. toctree::
   :maxdepth: 2
