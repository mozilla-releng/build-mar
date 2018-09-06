========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |codecov|
    * - package
      - |version| |downloads| |wheel| |supported-versions| |supported-implementations|

.. |docs| image:: https://readthedocs.org/projects/mar/badge/?style=flat
    :target: https://readthedocs.org/projects/mar
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/mozilla/build-mar.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/mozilla/build-mar

.. |codecov| image:: https://codecov.io/github/mozilla/build-mar/coverage.svg?branch=master
    :alt: Coverage Status
    :target: https://codecov.io/github/mozilla/build-mar

.. |version| image:: https://img.shields.io/pypi/v/mar.svg?style=flat
    :alt: PyPI Package latest release
    :target: https://pypi.org/project/mar/

.. |downloads| image:: https://img.shields.io/pypi/dm/mar.svg?style=flat
    :alt: PyPI Package monthly downloads
    :target: https://pypi.org/project/mar/

.. |wheel| image:: https://img.shields.io/pypi/wheel/mar.svg?style=flat
    :alt: PyPI Wheel
    :target: https://pypi.org/project/mar/

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/mar.svg?style=flat
    :alt: Supported versions
    :target: https://pypi.org/project/mar/

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/mar.svg?style=flat
    :alt: Supported implementations
    :target: https://pypi.org/project/mar/


.. end-badges

Package for handling Mozilla Archive files. MAR file format is documented at https://wiki.mozilla.org/Software_Update:MAR

* Free software: MPL 2.0 license

Usage
=====

To list the contents of a mar::

    mar -t complete.mar

To list the contents of a mar with extra detail::

    mar -T complete.mar

To extract a mar::

    mar -x complete.mar

To extract, and uncompress a bz2 compressed mar::

    mar -j -x complete.mar

To verify a mar::

    mar -k :mozilla-nightly -v complete.mar

To create a mar, using bz2 compression::

    mar -j -c complete.mar *

To create a mar, using xz compression::

    mar -J -c complete.mar *

To create a signed mar::

    mar -J -c complete.mar -k private.key -H nightly -V 123 tests

Installation
============

::

    pip install mar

Documentation
=============

https://mar.readthedocs.io/en/latest/

Development
===========

To run the all tests run::

    tox
