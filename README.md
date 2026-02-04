# Trout Snort Modules

[Snort](https://snort.org/) is one of the best, most robust open-source IPS available.
The third version is built around an open plugin architecture, enabling third-party extensions.

This repository contains the plugins we developed when embedding snort as the network analyzer in [Access Gate](https://www.trout.software/).

# Getting started

We currently only support building in an Alpine Linux enviroment, a bubblewrap Alpine environemnt is provided.

The project is built with [redo](https://redo.readthedocs.io/).

Unsure that you have both Bubblewrap and Redo installed on your host system.

To get started, first build and enter the alpine environment by exectuting:

```
test_envr_alpn/bshell.sh
```

This will take a bit of time the first time, as we download Alpine and build the image.

The bshell.sh command will (hopefully) leave you at an Alpine prompt.

In the main folder of the project you will find a number of scripts, to validate your installation you can run the build in test suite:

```
redo test
```

This will build snort, libdaq, our plugins, and execture the automated test.

To launch snort, use the snort.sh wrapper script, it takes the same arguments as a normal snort prompt, but will ensure the right libraries are picked up

```
./snort.sh --version
```

# Building

The scripts will ensure enough is build for running the individual scripts, if you want to get the debug and release builds without running snort, the following commands can be run explicitly

For a release build, run:

```
redo release
```

This populates p/install, where snort can be found in p/install/bin, libdaq in p/install/lib and the plugins (tm.so) in p/release

For debug builds, run:

```
redo debug
```

This populates p/install_debug, where snort can be found in p/install_debug/bin, libdaq in p/install_debug/lib and the plugins (tm.so) in p/debug


