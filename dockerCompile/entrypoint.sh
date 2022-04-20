#!/bin/sh

chmod +x waf-2.0.23

python3 ./waf-2.0.23 clean
python3 ./waf-2.0.23 distclean

python3 ./waf-2.0.23 configure

# First build will fail
python3 ./waf-2.0.23 build
# Because ns3module.cc is generated wrong
cp fixed-lte-bindings-ns3module.cc build/src/lte/bindings/ns3module.cc

# Also copy adapted version of network bindings
# as it contains additional bindings
cp fixed-network-bindings-ns3module.cc build/src/network/bindings/ns3module.cc
# Build again
python3 ./waf-2.0.23 build

exec "$@"
