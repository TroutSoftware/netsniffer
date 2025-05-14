
# TODO: We can detect which packages are installed without sudo, so we could
#       do the check and stop the build if some module is missing
echo "You may need to install dependencies by running ./install_deps " >&2

redo-ifchange envrc
. ./envrc

mkdir -p $BUILD_DIR
redo-ifchange bootstrap/deps bootstrap/snort
