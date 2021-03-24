#!/bin/sh

git clone https://github.com/gjcarneiro/pybindgen /pybindgen/
cd /pybindgen/
git checkout 823d8b2b

##############################################################################

## Optional

# Install this for --apiscan option

# wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
# cat get-pip.py | python
# rm get-pip.py

# apt install -y castxml
# pip install cxxfilt
# pip install pygccxml==1.9.0

##############################################################################

cd /ns3/

./waf clean
./waf distclean

./waf configure
./waf build

exec "$@"
