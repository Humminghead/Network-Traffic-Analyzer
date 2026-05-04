#!/bin/bash

# Variables
command=("pip3 list")
library=(pyelftools)

# Run
PY_LST_RESULT=$($command | grep $library)

# Prints:
# File descriptor 1 is the standard output (stdout).
# File descriptor 2 is the standard error (stderr).
if [[ ${PY_LST_RESULT+x} ]]; then
	printf '%s' "$PY_LST_RESULT">&1	
fi
