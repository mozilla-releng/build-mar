Changelog
=========
3.1.0 (2019-02-19)
------------------
* Added new autograph stage public key
* Dropped python3.5 support

3.0.0 (2018-09-06)
------------------
* Support extracting mar hash for external signing, and injecting signatures
  into unsigned files.
* File modes are set on extraction
* `mar -v` can now verify that unsigned mar files are well formed
* Added helper productinfo property to MarReader to allow convenient access to
  the product information information
* Internal signing API changed:
  * Got rid of Verifier/Signer classes
* Internal API for the mar format changed:
  * offets added for the beginning and end of signature and additional blocks
  * correctly represent additional section padding
* Support MAR files without additional sections

2.3.0 (2018-07-23)
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
