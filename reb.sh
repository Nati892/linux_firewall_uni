#!/bin/bash

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

echo "Starting kernel module rebuild process..."

# Try to remove existing module
echo "Removing existing module..."
rmmod firemod 2>/dev/null || echo "Module not loaded (this is OK)"

# Clean build files
echo "Cleaning build files..."
make clean

# Rebuild module
echo "Rebuilding module..."
if make; then
    echo "Build successful"
else
    echo "Build failed"
    exit 1
fi

# Insert new module
echo "Installing new module..."
if insmod firemod.ko; then
    echo "Module installed successfully"
    echo "Done! Module is ready"
else
    echo "Failed to install module"
    exit 1
fi

# Optional: Show module info
echo -e "\nModule information:"
lsmod | grep firemod
