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
    scripts=["scripts/mar.py"],
)
