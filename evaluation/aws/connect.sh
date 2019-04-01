#!/bin/bash

ssh -i "~/.ssh/hydrand.pem" -oStrictHostKeyChecking=accept-new -l ec2-user $1
