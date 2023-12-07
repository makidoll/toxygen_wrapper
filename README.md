# toxygen_wrapper

[ctypes](https://docs.python.org/3/library/ctypes.html)
wrapping of [Tox](https://tox.chat/)
[```libtoxcore```](https://github.com/TokTok/c-toxcore) into Python.
Taken from the ```wrapper``` directory of the now abandoned
<https://github.com/toxygen-project/toxygen> ```next_gen``` branch
by Ingvar.

The basics of NGC groups are supported, as well as AV and toxencryptsave.
There is no coverage of conferences as they are not used in ```toxygen```
and the list of still unwrapped calls as of Sept. 2022 can be found in
```tox.c-toxcore.missing```. The code still needs double-checking
that every call in ```tox.py``` has the right signature, but it runs
```toxygen``` with no apparent issues.

It has been tested with UDP and TCP proxy (Tor). It has ***not*** been
tested on Windows, and there may be some minor breakage, which should be
easy to fix. There is a good coverage integration testsuite in ```wrapper_tests```.
Change to that directory and run ```tests_wrapper.py --help```; the test
suite gives a good set of examples of usage.

## Install

Put the parent of the wrapper directory on your PYTHONPATH and
touch a file called `__init__.py` in its parent directory.

Then you need a ```libs``` directory beside the `wrapper` directory
and you need to link your ```libtoxcore.so``` and ```libtoxav.so```
and ```libtoxencryptsave.so``` into it. Link all 3 filenames
to ```libtoxcore.so``` if you have only ```libtoxcore.so```
(which is usually the case if you built ```c-toxcore``` with ```cmake```
rather than ```autogen/configure```). If you want to be different,
the environment variable TOXCORE_LIBS overrides the location of ```libs```.

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
```wrapper/tests_wrapper.py```.

## Prerequisites

No prerequisites in Python3.

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
  java, rust, scalla, go, etc. bindings instead.
  No support for NGC groups or toxencryptsave.

* <https://github.com/oxij/PyTox>
  forked from https://github.com/aitjcize/PyTox
  by Wei-Ning Huang <aitjcize@gmail.com>.
  Hardcore C wrapping which is not easy to keep up to date.
  No support for NGC or toxencryptsave. Abandonned.
  This was the basis for the TokTok/py-toxcore-c code until recently.

To our point of view, the ability of CTYPEs to follow code in the
debugger is a crucial advantage.

Work on this project is suspended until the
[MultiDevice](https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC) problem is solved. Fork me!
