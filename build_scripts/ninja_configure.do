redo-ifchange ../envrc

. ../envrc

redo-ifchange ninja_generate ../plugins.list
for m in $(cat ../plugins.list); do echo "$PD/$m/files.list"; done | xargs redo-ifchange

mkdir -p $BUILD_DIR/debug
mkdir -p $BUILD_DIR/release

# Making the build serious about warnings
CXXFLAGS="$CXXFLAGS -Wall -Wextra -Werror -Wpedantic -pedantic-errors"

#CXXFLAGS="$CXXFLAGS -Og -glldb" INSTALL_DIR="$INSTALL_DEBUG_DIR" ./ninja_generate > $BUILD_DIR/debug/build.ninja
CXXFLAGS="$CXXFLAGS -Og -g" INSTALL_DIR="$INSTALL_DEBUG_DIR" ./ninja_generate > $BUILD_DIR/debug/build.ninja
CXXFLAGS="$CXXFLAGS -O2" ./ninja_generate > $BUILD_DIR/release/build.ninja

redo-ifchange $BUILD_DIR/debug/build.ninja
redo-ifchange $BUILD_DIR/release/build.ninja
