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
- RPC server listening on HTTP. Acts as the Bob half of a key exchange and hands off exchanged keys
  to a user supplied callback.
- RPC client connecting over HTTP. Acts as the Alice half of a key exchange.
- Test that performs a full key exchange over a real socket on localhost.
