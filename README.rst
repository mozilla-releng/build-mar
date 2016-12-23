========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |appveyor| |requires|
        | |coveralls| |codecov|
    * - package
      - |version| |downloads| |wheel| |supported-versions| |supported-implementations|

.. |docs| image:: https://readthedocs.org/projects/mar/badge/?style=flat
    :target: https://readthedocs.org/projects/mar
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/mozilla/build-mar.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/mozilla/build-mar

.. |appveyor| image:: https://ci.appveyor.com/api/projects/status/github/mozilla/build-mar?branch=master&svg=true
    :alt: AppVeyor Build Status
    :target: https://ci.appveyor.com/project/mozilla/build-mar

.. |requires| image:: https://requires.io/github/mozilla/build-mar/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/mozilla/build-mar/requirements/?branch=master

.. |coveralls| image:: https://coveralls.io/repos/mozilla/build-mar/badge.svg?branch=master&service=github
    :alt: Coverage Status
    :target: https://coveralls.io/r/mozilla/build-mar

.. |codecov| image:: https://codecov.io/github/mozilla/build-mar/coverage.svg?branch=master
    :alt: Coverage Status
    :target: https://codecov.io/github/mozilla/build-mar

.. |version| image:: https://img.shields.io/pypi/v/mar.svg?style=flat
    :alt: PyPI Package latest release
    :target: https://pypi.python.org/pypi/mar

.. |downloads| image:: https://img.shields.io/pypi/dm/mar.svg?style=flat
    :alt: PyPI Package monthly downloads
    :target: https://pypi.python.org/pypi/mar

.. |wheel| image:: https://img.shields.io/pypi/wheel/mar.svg?style=flat
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/mar

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/mar.svg?style=flat
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/mar

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/mar.svg?style=flat
    :alt: Supported implementations
    :target: https://pypi.python.org/pypi/mar


.. end-badges

Package for handling Mozilla Archive files. MAR file format is documented at https://wiki.mozilla.org/Software_Update:MAR

* Free software: MPL 2.0 license

Installation
============

::

    pip install mar

Documentation
=============

https://mar.readthedocs.io/

Development
===========

To run the all tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
