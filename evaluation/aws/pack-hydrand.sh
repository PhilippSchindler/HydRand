#!/bin/bash

# change to aws directory
cd "$(dirname "$0")"
rm -f hydrand-base.zip
rm -f hydrand.zip

# change to directory in which the hydrand.py folder is
cd ../../..

rm -rf hydrand.py/logs/*

zip -X -r -9 hydrand.py/aws/hydrand-base.zip -r hydrand.py/lib     --include '*.py' '*.so'
zip -X -r -9 hydrand.py/aws/hydrand-base.zip -r hydrand.py/config  --exclude hydrand.py/config/network/**\*
zip -X -r -9 hydrand.py/aws/hydrand-base.zip -r \
    hydrand.py/hydrand/ed25519     \
    hydrand.py/hydrand/ed25519_ref \
    --include '*.py' '*.txt'

zip -X -r -9 hydrand.py/aws/hydrand.zip hydrand.py/logs
zip -X -r -9 hydrand.py/aws/hydrand.zip hydrand.py/config/network
zip -X -r -9 hydrand.py/aws/hydrand.zip hydrand.py/hydrand/*.py
zip -X -r -9 hydrand.py/aws/hydrand.zip hydrand.py/testing