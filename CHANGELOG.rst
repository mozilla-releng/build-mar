
Changelog
=========
2.3.0 (2018-04-12)
------------------
* Remove deprecated usage of signature generation and verification in
  cryptography library. This changes the type of object returned by the
  make_signer and make_verifier functions.

2.2.3 (2018-01-18)
------------------
* Update dependencies; dependencies are now also pinned in setup.py
* Correct the key size in exception messages
* Fix for construct 2.8.22 and higher
* Fix for hypothesis 3.44.16

2.2.2 (2017-07-06)
-----------------------------------------
* Fix bug when writing MAR files: the index size was incorrect
* Support writing interable streams
* Add new Mozilla SHA384 public keys

2.2.1 (2017-08-23)
-----------------------------------------
* Output compression and signature type

2.1.0 (2017-06-28)
-----------------------------------------
* Implement XZ compression

2.0.0 (2017-01-12)
-----------------------------------------
* First release on PyPI.
