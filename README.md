# toxygen_wrapper

ctypes wrapping of [Tox](https://tox.chat/) libtoxcore
<https://github.com/TokTok/c-toxcore> into Python.
Taken from the wrapper directory of the now abandoned
<https://github.com/toxygen-project/toxygen> `next_gen` branch
by Ingvar.
 
The basics of NGC groups are supported, as well as AV and toxencryptsave.
There is no coverage of conferences as they are not supported in ```toxygen```
and the list of still unwrapped calls as of Sept. 2022 can be found in
```tox.c-toxcore.missing```.

It has been tested with UDP and TCP proxy (Tor). It has ***not*** been
tested on Windows, and there may be some breakage, which should be
easy to fix. 

## Install

Put the parent of the wrapper directory on your PYTHONPATH and
touch a file called `__init__.py` in its parent directory.

## Prerequisites

No prerequisites in Python3.

## Other wrappers

There are a number of other wrappings into Python of Tox core.
This one uses CTYPES which has its merits - there is no need to
recompile anything as with Cython - change the Python file and it's done.
CTYPES code can be brittle, segfaulting if you've got things wrong,
but if your wrapping is right, it is very efficient and easy to work on.

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
