#!/bin/bash

scp -i "~/.ssh/hydrand.pem" $1 ec2-user@$2:/home/ec2-user

