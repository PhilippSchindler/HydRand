#!/bin/bash

TIME=`python -c "from datetime import datetime, timedelta; print(datetime.utcnow().replace(microsecond=0) + timedelta(seconds=20))"`

i3-msg workspace 7 &> /dev/null

i3-msg split horizontal

terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 0 -n 7 --start-at '$TIME' $@"  key Return


terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 1 -n 7 --start-at '$TIME' $@" key Return
i3-msg split vertical
terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 2 -n 7 --start-at '$TIME' $@" key Return

i3-msg focus parent

terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 3 -n 7 --start-at '$TIME' $@" key Return
i3-msg split vertical
terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 4 -n 7 --start-at '$TIME' $@" key Return
i3-msg focus parent

terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 5 -n 7 --start-at '$TIME' $@" key Return
i3-msg split vertical
terminator &> /dev/null & 
sleep 0.5
xdotool type --args 1 "pipenv run python hydrand 6 -n 7 --start-at '$TIME' $@" key Return
