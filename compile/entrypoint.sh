#!/bin/sh

wget https://waf.io/waf-2.0.22
chmod +x waf-2.0.22

python3 ./waf-2.0.22 clean
python3 ./waf-2.0.22 distclean

python3 ./waf-2.0.22 configure
# python3 ./waf-2.0.22 build

exec "$@"
