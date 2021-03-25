#!/bin/sh

chmod +x waf-2.0.22

python3 ./waf-2.0.22 clean
python3 ./waf-2.0.22 distclean

python3 ./waf-2.0.22 configure

# First build will fail
python3 ./waf-2.0.22 build
# Because ns3module.cc is generated wrong
cp fixed-lte-bindings-ns3module.cc build/src/lte/bindings/ns3module.cc
# Build again
python3 ./waf-2.0.22 build

exec "$@"
