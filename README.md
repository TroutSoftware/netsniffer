# Trout Snort Modules

[Snort](https://snort.org/) is one of the best, most robust open-source IPS available.
The third version is built around an open plugin architecture, enabling third-party extensions.

This repository contains the plugins we developed when embedding snort as the network analyzer in [Access Gate](https://www.trout.software/).

# Getting started

The project is built with [redo](https://redo.readthedocs.io/). To get started, run:

```
sh ./bootstrap/do
```

This will download and build snort, then our plugins, and run our tests.

You might need to install dependencies to build snort, using:
```
sh ./install_deps 
```

# Testing

Our test suite is executed via the small `sh3` Go runner.