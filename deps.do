cat bootstrap/deps | grep -v "^#" | xargs sudo apt-get -y install >&2
redo-ifchange bootstrap/deps bootstrap/snort
