redo-ifchange envrc deps

. ./envrc

redo-ifchange ninja_generate plugins.list
for m in $(cat plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/debug
mkdir -p $BUILD_DIR/release

# Making the build serious about warnings
CXXFLAGS="$CXXFLAGS -Wall -Wextra -Werror -Wpedantic"

CXXFLAGS="$CXXFLAGS -Og -g" ./ninja_generate > $BUILD_DIR/debug/build.ninja
CXXFLAGS="$CXXFLAGS -O2" ./ninja_generate > $BUILD_DIR/release/build.ninja

redo-ifchange $BUILD_DIR/debug/build.ninja
redo-ifchange $BUILD_DIR/release/build.ninja
