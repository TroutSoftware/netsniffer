## 2026-05-04

- Copied version 3.10.0.0 from https://github.com/snort3/snort3 into our core/ folder:

commit 3e6506be558215cf6e69c3fe7d22fc7acdfe23c3 (HEAD, tag: 3.10.0.0)
Author: Priyanka Gurudev (prbg) <prbg@cisco.com>
Date:   Tue Nov 25 19:14:39 2025 +0000

- Modified src/log/text_log.cc

With Musl fdopen won't fail if the filehandle given isn't in use, using fcntl to check it (see: https://github.com/snort3/snort3/issues/444 )

- Modified DHCPInfoEvent class in src/pub_sub/dhcp_events.h
- Added src/pub_sub/dhcp_events.cc
- Modified src/pub_sub/CMakeLists.txt to add dhcp_events.cc to build

On clang rtti doesn't work for classes that are declared multiple times, in order to fix this DHCPInfoEvent is now exported and it's made into a class with an explicit destructor to ensure a shared (linked) object is created to make RTTI work
