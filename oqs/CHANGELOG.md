# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.


## [Unreleased]
### Added
- Abstraction over `oqs-sys::rand` in the form of `OqsRand`.
- Abstraction over `oqs-sys::kex` in the form of `OqsKex`, `AliceMsg`, `BobMsg` and `SharedKey`.
- Benchmarks for all PRNG and kex algorithms.
- Tests for checking that serializing and deserializing the public messages work.

