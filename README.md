# toxygen_wrapper

ctypes wrapping of libtoxcore <https://github.com/TokTok/c-toxcore>
into Python. Taken from the now abandoned
<https://github.com/toxygen-project/toxygen> `next_gen` branch.

The basics of NGC groups are supported.

## Install

Put the parent of the wrapper directory on your PYTHONPATH and
touch a file called `__init__.py` in the parent directory.

## Prerequisites

No prerequisites.

# Other wrappers

There are a number of other wrappings into Python of Tox core.
This one uses CTYPES which has its merits - there is no need to
recompile anything as with Cython - change the Python file and it's done.

Others include:

* <https://github.com/TokTok/py-toxcore-c> Incomplete and not really
  actively supported. Maybe it will get worked on in the future,
  but TokTok seems to be working on java, rust, go, etc. bindings instead.

