#!/bin/bash

AWS_REGIONS=$(aws ec2 describe-regions --output text | awk '{print $3}' | xargs)
for each in ${AWS_REGIONS} ; do aws ec2 import-key-pair --key-name hydrand --public-key-material file://./hydrand.pub --region $each ; done


