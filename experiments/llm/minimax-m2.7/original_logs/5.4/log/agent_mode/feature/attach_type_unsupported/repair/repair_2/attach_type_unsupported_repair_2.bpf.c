#!/bin/bash

# Trigger sys_open by opening /dev/null
# This will be captured by the kprobe/do_sys_open BPF program

for i in $(seq 1 5); do
    # Use standard open() instead of openat2() for kernel 5.4 compatibility
    exec 3< /dev/null
    exec 3<&-
done

exit 0
