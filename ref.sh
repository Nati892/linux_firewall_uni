#!/bin/bash

echo "Unloading firemod module..."
sudo rmmod firemod.ko 2>/dev/null || echo "Module wasn't loaded"

echo "Clearing dmesg..."
sudo dmesg -c >/dev/null

echo "Loading firemod module..."
sudo insmod firemod.ko
if [ $? -ne 0 ]; then
    echo "Failed to load module!"
    exit 1
fi

echo "Module messages from dmesg:"
sudo dmesg -c | grep firemod

echo "Done!"
