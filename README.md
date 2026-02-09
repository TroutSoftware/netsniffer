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

To enable snort to capture packages from the network, we need to launch bubblewrap with sudo, and tweak the configuration a bit.

From you host system run the following script to get to an Alpine prompt where snort can run in promiscuous mode:

```
test_envr_alpn/bshell_capture.sh
```

The user needs to have sudo privileges and you might need to enter your password.

At the prompt this leaves you at, you can launch snort as usual (note, no sudo needed for this launch)

```
./snort.sh -c [config_script] -i [networkname]
```

_(Note, all the normal build commands also work in this capture environment, but I comes with the usual issues
running ninja builds and general file permissions, if files are changed from the prompt, (e.g. if redo format
is run) so consider your self as warned, and use at your own risk...)_


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


