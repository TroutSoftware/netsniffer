echo "You may need to install dependencies by running ./install_deps " >&2

redo-ifchange envrc
. ./envrc
mkdir -p p
redo-ifchange bootstrap/deps bootstrap/snort
