#!/bin/sh

./waf clean
./waf distclean

./waf configure
# ./waf build

exec "$@"
