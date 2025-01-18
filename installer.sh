#!/bin/bash

# Exit on any error
set -e

# Check for root privileges
if [ "$EUID" -ne 0 ]; then 
    echo "This script requires root privileges."
    echo "Please run with sudo."
    exec sudo "$0" "$@"
    exit
fi

echo "Starting installation of firewall project dependencies..."

# Update package list
echo "Updating package list..."
apt-get update

# Install basic build tools and kernel headers
echo "Installing build essentials and kernel headers..."
apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    gcc \
    make \
    git

# Install Python and pip
echo "Installing Python and pip..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv

# Install Qt dependencies
echo "Installing Qt dependencies..."
apt install -y \
    python3-pyqt6 \

# Create a Python virtual environment
echo "Creating Python virtual environment..."
if [ -d "venv" ]; then
    echo "Removing existing virtual environment..."
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python packages..."
pip install PyQt6 ipaddress

./build_install.sh
