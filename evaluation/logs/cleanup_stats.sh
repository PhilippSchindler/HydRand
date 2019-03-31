#!/bin/bash
# remove artefacts from _stats.log files

for d in */; do 
	cd "$d"
	for f in *_stats.log; do

		# delete all lines starting with \"
		sed -i -e '/^\"/ d' "$f"   
		
		# delte empty lines
  		sed -i -e '/^\s*$/d' "$f"

		echo "$f"
	done
	cd ..
done
