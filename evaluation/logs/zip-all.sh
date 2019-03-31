#!/bin/bash
# creates a zip files for each subdirectory

for i in */; do 
	zip -r "${i%/}.zip" "$i";
done
