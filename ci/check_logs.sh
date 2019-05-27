#!/bin/bash

# Fail fast if any commands exists with error
set -e

# Print all executed commands
set -x

for file in *.log; do
    for entry in "$(basename "$file")"; do
        if grep -q error: $entry; then
            echo "error(s) found in $file"
            exit 1
        fi
        if grep -q warning: $entry; then
            echo "warning(s) found in $file"
            exit 1
        fi
    done
done

exit 0
