# Extra Modules for Snort 

This repository contains new modules we found useful when deploying Snort in an advanced detection package.

## Running integration tests

The SH3 test runner is responsible for executing full module tests, usually against a recorded pcap.
With a modern Go version, install the script:

```
go install ./sh3
```

With `$HOME/go/bin` set in your path, all the `test` targets in makefiles should work.