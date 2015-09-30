from setuptools import setup, find_packages


setup(
    name="mar",
    version="1.2",
    author="Chris AtLee",
    author_email="catlee@mozilla.com",
    packages=find_packages(),
    url="https://github.com/mozilla/build-mar",
    license="MPL 2.0",
    description="MAR (Mozilla ARchive) Python implementation",
    long_description=open('README.md').read(),
    scripts=["scripts/mar.py"],
    install_requires=[
        "six",
    ],
)
