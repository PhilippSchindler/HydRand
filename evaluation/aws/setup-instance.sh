#!/bin/bash

yum install -y python3 dstat
python3 -m pip install --upgrade pip
python3 -m pip install pyzmq pytest sympy

# sympy is only required to run all tests