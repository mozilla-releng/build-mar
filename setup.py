# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from setuptools import setup, find_packages

setup(
    name="mar",
    version="1.4pre",
    author="Chris AtLee",
    author_email="catlee@mozilla.com",
    packages=find_packages(),
    url="https://github.com/mozilla/build-mar",
    license="MPL 2.0",
    description="MAR (Mozilla ARchive) Python implementation",
    install_requires=open('requirements.txt').readlines(),
    long_description=open('README.md').read(),
    scripts=["scripts/mar"],
)
