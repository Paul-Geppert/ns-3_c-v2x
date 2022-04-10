#!/bin/sh

./waf clean
./waf distclean

./waf configure

./waf --apiscan=lte

exec "$@"
