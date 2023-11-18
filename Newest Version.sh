#!/bin/bash

echo "Updating... this may take a couple minutes."
sudo -n apt-get update -y > file.log
echo "Successfully updated."
echo "Upgrading... this may take a couple minutes."
sudo -n apt-get upgrade -y > file.log
echo "Successfully upgraded. Your device is now up to date."
