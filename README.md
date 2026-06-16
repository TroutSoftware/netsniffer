# Trout Snort Modules

[Snort](https://snort.org/) is one of the best, most robust open-source IPS available.
The third version is built around an open plugin architecture, enabling third-party extensions.

This repository contains our modified version of snort with some new plugins we developed when embedding snort as the network analyzer in [Access Gate](https://www.trout.software/).

# Getting started

We currently only support building in an Alpine Linux enviroment on a Linux host, a bubblewrap Alpine environemnt is provided.

(A native build might work if you have the LLVM toolchain installed)

Ensure that you have Bubblewrap installed on your host system.

To get started, first run setup.sh to configure your build folder with something like:


```
../netsniffer $ ./setup.sh --mode=RELEASE --target=ALPINE --output=my_build_folder
```

This will take a bit of time the first time, as we download Alpine and build the image.

After the setup is complete you can now change to you my_build_folder and run snort

```
../my_build_folder $ ./snort.sh --help
```

To run the test suite, you need to have go installed, and then run

```
../my_build_folder $ ./sh3_test_all.sh
```

To launch snort in the debugger, run

```
../my_build_folder $ ./lldb_snort.sh
```

Finally the clangd server can be launched with

```
../my_build_folder $ ./clangd.sh
```
