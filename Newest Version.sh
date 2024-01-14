#!/bin/bash
# Update system packages and upgrade
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get uninstall ophcrack -y
# Clean up the system
sudo apt-get autoremove -y && sudo apt-get autoclean -y
read -p "Do you want to delete .mp3 and .mp4 files? (y/n): " answer
if [[ $answer == "y" ]]; then
  # Find all .mp3 and .mp4 files
  files=$(find /path/to/directory -type f \( -name "*.mp3" -o -name "*.mp4" \))

  if [[ -n $files ]]; then
    echo "Found the following files:"
    echo "$files"

    # Delete the files
    rm -f $files
    echo "Files deleted successfully."
  else
    echo "No .mp3 or .mp4 files found."
  fi
else
  echo "No files will be deleted."
fi

# Flush existing rules
sudo iptables -F
# Default policy to drop all incoming packets
sudo iptables -P INPUT DROP
# Accept incoming packets on loopback
sudo iptables -A INPUT -i lo -j ACCEPT
# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Clear the terminal if requested
read -p "Do you want to clear the terminal? (y/n): " clear_terminal
if [[ $clear_terminal == "y" ]]; then
  sudo clear
fi

# Monitor user logins
echo "User login report for $(date)" > /var/log/userlogin.log
who >> /var/log/userlogin.log

# Fail2Ban installation and configuration
sudo apt-get install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo service fail2ban start

# Check for failed login attempts
grep "Failed password" /var/log/auth.log > /var/log/failed-login-attempts.log

# Backup /etc directory
tar -czf /backup/etc-$(date +%F).tar.gz /etc

# Update and upgrade the system
sudo apt-get update -y && sudo apt-get upgrade -y

# Quarantine folder on the desktop
QUARANTINE_FOLDER="$HOME/Desktop/Quarantine"

# Create quarantine folder if it doesn't exist
mkdir -p "$QUARANTINE_FOLDER"

# Run ClamAV scan on the entire system
echo "Scanning the entire system for potential malware..."
sudo clamscan -r --move="$QUARANTINE_FOLDER" --infected /

# Remove execute permission for detected malware
if [ -d "$QUARANTINE_FOLDER" ]; then
    echo "Removing execute permission for potential malware in the quarantine folder..."
    find "$QUARANTINE_FOLDER" -type f -exec chmod -x {} \;
fi

# Clear the terminal if requested
read -p "Do you want to clear the terminal? (y/n): " clear_terminal
if [[ $clear_terminal == "y" ]]; then
  sudo clear
fi

echo "Scan and quarantine process completed."
# Enable UFW
sudo ufw enable
# Allow SSH connections
sudo ufw allow ssh
# Allow HTTP connections
sudo ufw allow http
# Allow HTTPS connections
sudo ufw allow https

# Install unattended-upgrades package
sudo apt-get install unattended-upgrades -y
# Enable automatic updates
sudo dpkg-reconfigure -plow unattended-upgrades

# Edit SSH configuration file
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
# Restart SSH service
sudo service ssh restart

# Enable firewall logging
sudo ufw logging on

# Enable automatic security updates
sudo apt-get install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic security updates for specific packages
echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | sudo debconf-set-selections
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic security updates for kernel packages
echo 'unattended-upgrades unattended-upgrades/enable_kernel_auto_upgrades boolean true' | sudo debconf-set-selections
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic security updates for security-related packages only
echo 'unattended-upgrades unattended-upgrades/allowed_origins string ${distro_id}:${distro_codename}-security' | sudo debconf-set-selections
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic security updates for all packages
echo 'unattended-upgrades unattended-upgrades/allowed_origins string ${distro_id}:${distro_codename} ${distro_id}:${distro_codename}-security' | sudo debconf-set-selections
sudo dpkg-reconfigure -plow unattended-upgrades

# Enable automatic security updates for all packages and reboot if necessary
echo 'unattended-upgrades unattended-upgrades/automatic_reboot boolean true' | sudo debconf-set-selections
sudo dpkg-reconfigure -plow unattended-upgrades

# Clear the terminal if requested
read -p "Do you want to clear the terminal? (y/n): " clear_terminal
if [[ $clear_terminal == "y" ]]; then
  sudo clear
fi

# Remove unauthorized administrators from sudo group
echo "Enter a list of authorized administrators (separated by spaces): "
read -a authorized_admins

for user in $(getent passwd | cut -d: -f1); do
  if [[ ! " ${authorized_admins[@]} " =~ " $user " ]] && [[ ! "$user" =~ ^(_|root|ubuntu) ]]; then
    # Prompt the user for confirmation before removing the user from the sudo group
    read -p "Are you sure you want to remove user $user from the sudo group? (y/n): " confirm
    if [[ $confirm == "y" ]]; then
      # Remove the user from the sudo group
      sudo deluser $user sudo
    fi
  fi
done

# Prompt the user to enter a list of authorized system users
echo "Enter a list of authorized system users (separated by spaces): "
read -a authorized_users

# Iterate over all users in the system
for user in $(getent passwd | cut -d: -f1); do
  # Check if the user is not in the list of authorized users and is not a system user
  if [[ ! " ${authorized_users[@]} " =~ " $user " ]] && [[ ! "$user" =~ ^(_|root|ubuntu) ]]; then
    # Prompt the user for confirmation before deleting the user
    read -p "Are you sure you want to delete user $user? (y/n): " confirm
    if [[ $confirm == "y" ]]; then
      # Delete the user and remove their home directory
      sudo userdel -r $user
    fi
  fi
done

# Function to generate a secure randomized password
generate_password() {
  local length=$1
  local password=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1)
  echo "$password"
}

# Generate 5 secure randomized passwords
for i in {1..5}; do
  password=$(generate_password 12)
  echo "Secure Randomized Password $i: $password"
done

# Clear the terminal if requested
read -p "Do you want to clear the terminal? (y/n): " clear_terminal
if [[ $clear_terminal == "y" ]]; then
  sudo clear
fi
# Enforce strong password policies
sudo apt-get install libpam-pwquality -y
sudo sed -i 's/password        requisite                       pam_pwquality.so retry=3/password        requisite                       pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

