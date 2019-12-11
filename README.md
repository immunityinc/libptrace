# libptrace

libptrace is an event driven process/thread debugging, tracing, and
manipulation framework.  It is written in C and has Python 2.7 and 3.7
bindings.

It is meant to be used as a library.  The API has been designed with
cross-platform support in mind.  Although the current version only runs on 32-
and 64-bit (wow64 is supported) versions of Windows the design and abstractions
are such that other platforms and even remote debugging support can be added
under the same API.

It is multiple core/thread aware, and can easily be used to run multiple event
loops concurrently.  Debugging process groups or pipelines or tracing a large
number of processes can be scaled by increasing execution cores this way.


## Foreword

I wrote the initial version of libptrace in 2006 while still in university, and
re-licensed it for full use by Immunity Inc. in 2011, my employer at the time.
Around this time the framework was meant to be integrated in Immunity Debugger,
although I have always taken care to keep the framework separate, so it could
be used in a stand-alone fashion.

With this goal in mind it saw a lot of development at Immunity, and I am
grateful to have been able to actively develop on it during my working hours
and see the framework become more mature.  I redesigned most of it to be aware
of multiple cores, to provide Python bindings, and create better abstractions.

With the eventual release of x64dbg it was decided we would no longer work on
Immunity Debugger, and instead focus our efforts on other things.  This also
stalled libptrace development, and for the following years it collected dust in
the internal git repository, until after the acquisition of Immunity Inc. by
Cyxtera Technologies, now under Cyxtera Cybersecurity Inc., it was decided to
release the project under the LGPL version 2.1 so it could hopefully see
adoption and further development.

I want to kindly thank Immunity Inc., as well as Cyxtera Technologies, and
Cyxtera Cybersecurity Inc. for making this release happen.  Also I'd like to
specifically thank Dave Aitel for pushing this release through layers of
management and shielding me from the bureaucratic parts of the process.  It
would have been sad to see my labor lost and without purpose, and without
their willingness to release the libptrace development that was done internally
as open source this is what would have happened.

I also want to thank several coworkers that spent time using or working on the
framework, most notably Massimiliano Oldani, Roderick Asselineau, and Christos
Kalkanis.  My thanks also extends to Lennert Buytenhek for his intrusive AVL
tree and linked list implementations which I ended up using.

Although it has been over 4 years since any work has been done on the project,
I hope people will find it useful.  I believe the design and source code are
relatively clean, and at this point allows the framework to be extended and
ported to other platforms relatively easily.  Hopefully one day this can turn
into a true cross-platform debugging library under a single consistent API.

Finally, I'd like to dedicate this project to my lost daughter, Yuzuyu Huizer,
with whom I hope to one day reunite.  I love you.

  -- Ronald Huizer <rhuizer@hexpedition.com>

## Building

The current supported build method is by cross-compiling the project using
MinGW and CMake.  The build system has been tested on Ubuntu 19.04.

A 32-bit installer can be built using:
```
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=mingw-w64-x86.cmake .
make
makensis libptrace-setup.nsi
```

A 64-bit bit installer can be built using:
```
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=mingw-w64-x64.cmake .
make
makensis -DUSE64 libptrace-setup.nsi
```

## Installation

After following the build steps above, the 32-bit installer will be at
`libptrace-setup32.exe` and the 64-bit installer will be at
`libptrace-setup64.exe`.

The installer will automatically determine what versions of Python are
installed and whether they are 32-bit or 64-bit.  The versions that were found
will be offered by the installer, and versions that were not found will be
grayed out.

Release downloads can be found
[here](https://github.com/immunityinc/libptrace/releases).

## Examples

The `doc/` directory is hopelessly outdated.  It is included as a starting
point for more current documentation.  Please do not use it.

Several example scripts can be found in the `python/scripts` directory.  They
will be installed to `Program Files\Immunity Inc\libptrace` or in case of the
32-bit version `Program Files (x86)\Immunity Inc\libptrace`.

These examples do in no way show the framework exhaustively, but they should
provide a good starting point for anyone that wants to use the framework.  The
C API has not been documented well, but some examples can be found in the
`unittests/windows` directory.  The `python/` directory which contains the
python bindings also provides a good overview.  Finally, the
`include/libptrace` directory contains the header files which are public, and
as such provide a good list of API functions.

It should be noted the Python API is currently a fairly limited subset of the
C API.

### A python example

As an example, the general workflow to trace `RegOpenKeyExW` calls in an
executable would be:
```
import _ptrace

def bp_handler(bp, thread):
    (key, subkey, options, sam, result) = _ptrace.cconv.args_get(thread, "%u%p%u%u%p")
    subkey = thread.process.read_utf16(subkey)
    print('T{}: RegOpenKeyEx({}, "{}", 0x{:08x}, 0x{:08x}, 0x{:08x})'
          .format(thread.id, key, subkey, options, sam, result), end='')

def attached_handler(process):
    bp = _ptrace.breakpoint_sw("advapi32!RegOpenKeyExW", bp_handler)
    process.breakpoint_set(bp)

handlers          = _ptrace.event_handlers()
handlers.attached = attached_handler

_ptrace.execv(r"C:\Windows\Notepad.exe", [], handlers, 0)
_ptrace.main()
```

If the return value of `RegOpenKeyExW` is also desired, it is easiest to set
a breakpoint on the return address of the function call.  This avoids the
need for code analysis to determine function exit paths statically:
```
def bp_end_handler(bp, thread):
    print("=", _ptrace.cconv.retval_get(thread))

def bp_handler(bp, thread):
    (key, subkey, options, sam, result) = _ptrace.cconv.args_get(thread, "%u%p%u%u%p")
    subkey = thread.process.read_utf16(subkey)
    print('T{}: RegOpenKeyEx({}, "{}", 0x{:08x}, 0x{:08x}, 0x{:08x})'
          .format(thread.id, key, subkey, options, sam, result), end='')

    retaddr = _ptrace.cconv.retaddr_get(thread)
    if thread.process.breakpoint_find(retaddr) is None:
        bp_end = _ptrace.breakpoint_sw(retaddr, bp_end_handler)
        thread.process.breakpoint_set(bp_end)
```

## Copyright

The copyright situation is made clear in each individual file.  They are mostly
held by Cyxtera Cybersecurity Inc., Ronald Huizer, or both at the same time. A
select few files have third party copyright holders, such as Lennert Buytenhek.

## License

Distributed under version 2.1 of the GNU Lesser General Public License. See
`COPYING` and `COPYING.LESSER` for more information.

## Authors

* [Ronald Huizer](https://github.com/rhuizer/) - project design and implementation
* Massimiliano Oldani - symbol handling, bug fixes
* Roderick Asselineau - pe improvements, interval tree, bug fixes
* Christos Kalkanis - testing, improvements, bug fixes

## Contact

* Ronald Huizer - rhuizer@hexpedition.com -
  [@ronaldhuizer](https://twitter.com/ronaldhuizer)

## Acknowledgments

* Immunity Inc. and Cyxtera Cybersecurity Inc. for making this release happen.
* [Lennert Buytenhek](https://github.com/buytenh/) for his intrusive AVL tree
  and linked list implementation.
* Dave Aitel for dealing with the bureaucratic and legal parts of this release.
