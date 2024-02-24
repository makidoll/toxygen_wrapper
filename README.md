# toxygen_wrapper

[ctypes](https://docs.python.org/3/library/ctypes.html)
wrapping of [Tox](https://tox.chat/)
[```libtoxcore```](https://github.com/TokTok/c-toxcore) into Python.
Taken from the ```wrapper``` directory of the now abandoned
<https://github.com/toxygen-project/toxygen> ```next_gen``` branch
by Ingvar.

The basics of NGC groups are supported, as well as AV and toxencryptsave.
There is no coverage of conferences as they are not used in ```toxygen```
and the list of still unwrapped calls as of Feb. 2024 can be found in
```tox.c-toxcore.missing```. The code is typed so that every call in
```tox*.py``` should have the right signature, and it runs
```toxygen``` with no apparent issues.

It has been tested with UDP and TCP proxy (Tor). It has ***not*** been
tested on Windows, and there may be some minor breakage, which should be
easy to fix. There is a good coverage integration testsuite in ```toxygen_wrapper/tests```.
Change to that directory and run ```tests_wrapper.py --help```; the test
suite gives a good set of examples of usage.

## Install

Edit the Makefile and run ```make install``` or ```cd src```
and run ```toxygen_wrapper/tests/tests_wrapper.py```

Then you need a ```libs``` directory beside the ```toxygen_wrapper``` directory
and you need to link your ```libtoxcore.so``` and ```libtoxav.so```
and ```libtoxencryptsave.so``` into it. Link all 3 filenames
to ```libtoxcore.so``` if you have only ```libtoxcore.so```
(which is usually the case if you built ```c-toxcore``` with ```cmake```
rather than ```autogen/configure```). If you want to be different,
the environment variable TOXCORE_LIBS overrides the location of ```libs```;
look in the file ```toxygen_wrapper/libtox.py``` for the details.

# Tests

To test, run ```python3 src/toxygen_wrapper/tests/tests_wrapper.py --help```

As is, the code in ```tox.py``` is very verbose. Edit the file to change
```
def LOG_ERROR(a): print('EROR> '+a)
def LOG_WARN(a): print('WARN> '+a)
def LOG_INFO(a): print('INFO> '+a)
def LOG_DEBUG(a): print('DBUG> '+a)
def LOG_TRACE(a): pass # print('TRAC> '+a)
```
to all ```pass #``` or use ```logging.logger``` to suite your tastes.
```logging.logger``` can be dangerous in callbacks in ```Qt``` applications,
so we use simple print statements as default. The same applies to
```toxygen_wrapper/tests/tests_wrapper.py```.

## Prerequisites

No prerequisites in Python3.

Because this is using Ctypes, you can run it under a python-enabled gdb,
which if you compiled the c-toxcore library ```-DCMAKE_BUILD_TYPE="Debug"```
means that you can run both the Python and the C under gdb. This is HUGE!
The incantation is something like this:
```
gdb -ex r --args /usr/bin/python3 src/toxygen_wrapper/tests/tests_wrapper.py
```
with some suitable settings of PYTHONPATH and maybe LD_LIBRARY_PATH.

## Other wrappers

There are a number of other wrappings into Python of Tox core.
This one uses [ctypes](https://docs.python.org/3/library/ctypes.html)
which has its merits - there is no need to recompile anything as with
Cython - change the Python file and it's done. And you can follow things
in a Python debugger, or with the utterly stupendous Python feature of
```gdb``` (```gdb -ex r --args /usr/bin/python3.9 <pyfile>```).

CTYPES code can be brittle, segfaulting if you've got things wrong,
but if your wrapping is right, it is very efficient and easy to work on.
The [faulthandler](https://docs.python.org/3/library/faulthandler.html)
module can be helpful in debugging crashes
(e.g. from segmentation faults produced by erroneous C library wrapping).

Others include:

* <https://github.com/TokTok/py-toxcore-c> Cython bindings.
  Incomplete and not really actively supported. Maybe it will get
  worked on in the future,  but TokTok seems to be working on
  java, go, etc. bindings instead. Based on a homebrew generator written
  in undocumented, uncommented code in a language almost nobody knows, or has.
  No support for NGC groups; no significant tests.

* <https://github.com/oxij/PyTox>
  forked from https://github.com/aitjcize/PyTox
  by Wei-Ning Huang <aitjcize@gmail.com>.
  Hardcore C wrapping which is not easy to keep up to date.
  No support for NGC but good tests. Abandonned.
  This was the basis for the TokTok/py-toxcore-c code until recently.

To our point of view, the ability of CTYPEs to follow code in the
debugger is a crucial advantage.

## Updates

Although Tox works over Tor, we do not recommend its usage for
anonymity as it leaks DNS requests due to a 6-year old known security
issue: https://github.com/TokTok/c-toxcore/issues/469 unless your Tox client
does hostname lookups before calling Tox (like toxygen does). Otherwise,
do not use it for anonymous communication unless you have a firewall in place.

The Tox project does not follow semantic versioning of its main structures
so the project may break the underlying ctypes wrapper at any time;
it's not possible to use Tox version numbers to tell what the API will be.
In which case you'll have to go into the tox.py file in
https://git.plastiras.org/emdee/toxygen_wrapper to fix it yourself.
The last tested git commit is 5dd9ee3f65423a4095cacb8396a5d406a27610c7
2024-02-10

Up-to-date code is on https://git.plastiras.org/emdee/toxygen_wrapper

Work on this project is suspended until the
[MultiDevice](https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC) problem is solved. Fork me!

