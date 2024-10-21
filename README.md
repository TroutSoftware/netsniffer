# Extra Modules for Snort 

This repository contains new modules we found useful when deploying Snort in an advanced detection package.

## Running integration tests

NOTE: This information is out of date (quick fix: to build and run tests do a 'make test' from the root folder)

The SH3 test runner is responsible for executing full module tests, usually against a recorded pcap.
With a modern Go version, install the script:

```
go install ./sh3
```

With `$HOME/go/bin` set in your path, all the `test` targets in makefiles should work.
