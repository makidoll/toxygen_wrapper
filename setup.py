import sys
import os
from setuptools import setup
from setuptools.command.install import install

version = '1.0.0'

setup(name='tox_wrapper',
      version=version,
      description='Tox ctypes wrapping into Python',
      long_description='Tox ctypes wrapping of c-toxcore into Python3',
      url='https://git.plastiras.org/emdee/toxygen/',
      keywords='ctypes Tox messenger',
      author='Ingvar',
      maintainer='',
      license='GPL3',
      packages=['tox_wrapper'],
      install_requires=['ctypes'],
      include_package_data=True,
      # dont run directly if you need a proxy
      # run python3 tox_wrapper/tests/tests_wrapper.py --help
      test_suite="tox_wrapper.tests.tests_wrapper.main",
      classifiers=[
            "Environment :: Console",
            "Topic :: Internet",
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3",
            "License :: OSI Approved",
            ],
      zip_safe=False
      )
