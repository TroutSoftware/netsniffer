cat bootstrap/deps | grep -v "^#" | xargs sudo apt-get -y install >&2
mkdir -p p
redo-ifchange bootstrap/deps bootstrap/snort
