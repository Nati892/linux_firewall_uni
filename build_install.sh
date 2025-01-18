#!/bin/bash

# Check for sudo FIRST before any other operations
if [ "$EUID" -ne 0 ]; then 
    echo "This script requires root privileges."
    echo "Please run with sudo."
    exec sudo "$0" "$@"
    exit
fi

# Update package list
echo "Updating package list..."
apt-get update

# Install required packages
echo "Installing required packages..."
apt-get install -y gcc make linux-headers-$(uname -r)

echo "install started"

# Create the directory before trying to copy to it
mkdir -p /lib/modules/$(uname -r)/extra/

# Build the module using existing Makefile
echo "Building kernel module..."
make

# Check if the build was successful
if [ ! -f firemod.ko ]; then
    echo "Error: Module compilation failed or module file not found!"
    exit 1
fi

# Copy the built module to the startup directory
echo "Installing kernel module..."
cp firemod.ko /lib/modules/$(uname -r)/extra/

# Update module dependencies
echo "Updating module dependencies..."
depmod -a

# Load the module immediately
echo "Loading kernel module..."
modprobe firemod || insmod /lib/modules/$(uname -r)/extra/firemod.ko

# Add module to load at startup
echo "Configuring module to load at startup..."
echo "firemod" > /etc/modules-load.d/custom_module.conf

echo "Installation complete!"
