#!/bin/bash
#
#CIS Hardening Script for Ubuntu Server 18.04 LTS

#######################################################################################################

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'

#######################################################################################################

#check root user
if [[ $EUID -ne 0 ]]; then 
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

#######################################################################################################

#Input for IP or Domain
function domain_checker() {
    local INPUT=$1
    if [[ $INPUT =~ ^[a-z|A-Z|0-9]+\.+[a-z|A-Z]+$ ]] || [[ $INPUT =~ ^[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.[a-z|A-A]+$ ]] || [[ $INPUT =~ ^[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.[a-z|A-A]+$ ]] || [[ $INPUT =~ ^[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.+[a-z|A-Z|0-9]+\.[a-z|A-A]+$ ]]; then 
        return 0
    else 
        return 1
    fi 
}

function ip_checker() {
    local INPUT=$1
    if [[ $INPUT =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else 
        return 1
    fi  
}

#######################################################################################################

#Set permanent nameserver
function change_nameserver () {
  apt-get update
  apt install resolvconf -y
  echo "nameserver 8.8.8.8" >> /etc/resolvconf/resolv.conf.d/head
  echo "nameserver 4.2.2.4" >> /etc/resolvconf/resolv.conf.d/head
  resolvconf -u
  echo "nameserver 8.8.8.8" >> /etc/resolv.conf
  echo "nameserver 4.2.2.4" >> /etc/resolv.conf
}

#######################################################################################################

#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)
function 1.1.1.1 (){
  echo -e "${RED}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
  modprobe -n -v cramfs | grep "true" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^cramfs\s" && rmmod cramfs
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of cramfs filesystems is disabled"
  fi
}


#######################################################################################################

#1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Automated)
function 1.1.1.2 (){
  echo -e "${RED}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
  modprobe -n -v freevxfs | grep "true" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^freevxfs\s" && rmmod freevxfs
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of freevxfs filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Automated)
function 1.1.1.3 (){
  echo -e "${RED}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
  modprobe -n -v jffs2 | grep "true" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^jffs2\s" && rmmod jffs2
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of jffs2 filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Automated)
function 1.1.1.4 (){
  echo -e "${RED}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
  modprobe -n -v hfs | grep "true" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^hfs\s" && rmmod hfs
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfs filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Automated)
function 1.1.1.5 (){
  echo -e "${RED}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
  modprobe -n -v hfsplus | grep "true" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^hfsplus\s" && rmmod hfsplus
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of hfsplus filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.1.6 Ensure mounting of udf filesystems is disabled (Automated)
function 1.1.1.6_udf (){
  echo -e "${RED}1.1.1.6${NC} Ensure mounting of udf filesystems is disabled"
  modprobe -n -v udf | grep "true" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^udf\s" && rmmod udf
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of udf filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored) - CIS_Ubuntu_Linux_18.04_LTS_Benchmark_v2.0.1
function 1.1.1.6_squashfs (){
  echo -e "${RED}1.1.1.6${NC} Ensure mounting of squashfs filesystems is disabled"
  modprobe -n -v squashfs | grep "true" || echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^squashfs\s" && rmmod squashfs
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure mounting of squashfs filesystems is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure mounting of squashfs filesystems is disabled"
  fi
}

#######################################################################################################

#1.1.3 Ensure nodev option set on /tmp partition
#1.1.4 Ensure nosuid option set on /tmp partition
#1.1.5 Ensure noexec option set on /tmp partition
function 1.1.3_4_5 (){
  #set default status
  policystatus=1

  if grep -qs '/tmp' /proc/mounts; then 
      if [ -f /etc/fstab ]; then
          FSTAB_TMP_OPTIONS=`grep -v '^#' /etc/fstab | grep '/tmp' /etc/fstab | awk '{print $4}'`
          sed -i "s@$FSTAB_TMP_OPTIONS@$FSTAB_TMP_OPTIONS,nodev,nosuid,noexec@"  /etc/fstab
          mount -o $FSTAB_TMP_OPTIONS,nodev,nosuid,noexec /tmp
          policystatus=0
      elif [ -f /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then 
          TMP_MOUNT_OPTIONS=`grep 'Options' /etc/systemd/system/local-fs.target.wants/tmp.mount`
          sed -i "s@$TMP_MOUNT_OPTIONS@$TMP_MOUNT_OPTIONS,nodev,nosuid,noexec@" /etc/systemd/system/local-fs.target.wants/tmp.mount
          systemctl daemon-reload
          systemctl restart tmp.mount
          policystatus=0
      fi 

      policystatus=1
  else 
      policystatus=1
  fi 

  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
      echo -e "${GREEN}Remediated:${NC} Ensure nodev,nosuid,noexec option set on /tmp partition"
  else
      echo -e "${RED}UnableToRemediate:${NC} Ensure nodev,nosuid,noexec option set on /tmp partition"
  fi
}

#######################################################################################################

#1.1.8 Ensure nosuid option set on /var/tmp partition
#1.1.9 Ensure noexec option set on /var/tmp partition

function 1.1.1.8_9 (){
  # set default status
  policystatus=1

  if grep -qs '/var/tmp' /proc/mounts; then 
      if [ -f /etc/fstab ]; then
          FSTAB_VAR_TMP_OPTIONS=`grep -v '^#' /etc/fstab | grep '/var/tmp' /etc/fstab | awk '{print $4}'`
          sed -i "s@$FSTAB_VAR_TMP_OPTIONS@$FSTAB_VAR_TMP_OPTIONS,nodev,nosuid,noexec@"  /etc/fstab
          mount -o $FSTAB_VAR_TMP_OPTIONS,nodev,nosuid,noexec /var/tmp
          policystatus=0
      fi 

      policystatus=1
  else 
      policystatus=1
  fi 

  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
      echo -e "${GREEN}Remediated:${NC} Ensure nodev,nosuid,noexec option set on /var/tmp partition"
  else
      echo -e "${RED}UnableToRemediate:${NC} Ensure nodev,nosuid,noexec option set on /var/tmp partition"
  fi
}

#######################################################################################################

#1.1.6 Ensure /dev/shm is configured (Automated)
function 1.1.6 (){
  echo -e "${RED}1.1.6${NC} Ensure /dev/shm is configured (Automated)"
  findmnt /dev/shm | grep -i "noexec" || echo -e "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure /dev/shm is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure /dev/shm is configured"
  fi
}

#######################################################################################################

#1.1.13 Ensure nodev option set on /home partition
function 1.1.13 (){
  # set default status
  policystatus=1

  if grep -qs '/home' /proc/mounts; then 
      if [ -f /etc/fstab ]; then
          FSTAB_HOME_OPTIONS=`grep -v '^#' /etc/fstab | grep '/home' /etc/fstab | awk '{print $4}'`
          sed -i "s@$FSTAB_HOME_OPTIONS@$FSTAB_HOME_OPTIONS,nodev@"  /etc/fstab
          mount -o $FSTAB_HOME_OPTIONS,nodev /home
          policystatus=0
      fi 

      policystatus=1
  else 
      policystatus=1
  fi 

  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
      echo -e "${GREEN}Remediated:${NC} Ensure nodev option set on /home partition"
  else
      echo -e "${RED}UnableToRemediate:${NC} Ensure nodev option set on /home partition"
  fi
}
#######################################################################################################

#1.1.22 Ensure sticky bit is set on all world-writable directories (Automated)
function 1.1.22_sticky (){
  echo -e "${RED}1.1.20${NC} Ensure sticky bit is set on all world-writable directories"
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure sticky bit is set on all world-writable directories"
  fi
}
#######################################################################################################

#1.1.22 Disable Automounting (Automated)
function 1.1.22 (){
  echo -e "${RED}1.1.22${NC} Disable Automounting"
  systemctl disable autofs.service
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Disable Automounting"
  else
    echo -e "${RED}UnableToRemediate:${NC} Disable Automounting"
  fi
}
#######################################################################################################

#1.1.24 Disable USB Storage (Automated)
function 1.1.24 (){
  echo -e "${RED}1.1.24${NC} Disable USB Storage"
  modprobe -n -v usb-storage | grep "^install /bin/true$" || echo "install usb-storage /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^usb-storage\s" && rmmod usb-storage
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Disable USB Storage"
  else
    echo -e "${RED}UnableToRemediate:${NC} Disable USB Storage"
  fi
}
#######################################################################################################

#1.3.2 Ensure sudo commands use pty (Scored)
function 1.3.2_sudo (){
  grep -i "Defaults use_pty" /etc/sudoers /etc/sudoers.d/* || echo "Defaults use_pty" >> /etc/sudoers
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure sudo commands use pty"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure sudo commands use pty"
  fi
}

#######################################################################################################

#1.3.3 Ensure sudo log file exists (Scored)
function 1.3.3 (){
  grep -i "logfile" /etc/sudoers /etc/sudoers.d/* || echo "Defaults logfile="/var/log/sudo.log"" >> /etc/sudoers
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} 1.3.3 Ensure sudo log file exists (Scored)"
  else
    echo -e "${RED}UnableToRemediate:${NC} 1.3.3 Ensure sudo log file exists (Scored)"
  fi
}
#######################################################################################################

#1.4.1 Ensure permissions on bootloader config are not overridden (Automated)
function 1.4.1 (){
  echo -e "${RED}1.4.1${NC} Ensure permissions on bootloader config are not overridden"
  sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
  sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
  fi
}
#######################################################################################################

#1.4.2 Ensure bootloader password is set (Automated)
function 1.4.2 (){
  while true; do 
    grub-mkpasswd-pbkdf2 | tee /tmp/grubpassword.tmp
    if [ $(cat /tmp/grubpassword.tmp | wc -l) -gt 2 ]; then 
      break
    fi
  done 

  local grubpassword=$(cat /tmp/grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
  echo " set superusers="root" " >> /etc/grub.d/40_custom
  echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
  rm /tmp/grubpassword.tmp
  update-grub
}
#######################################################################################################

#1.4.3 Ensure permissions on bootloader config are configured (Automated)
function 1.4.3 (){
  echo -e "${RED}1.4.3${NC} Ensure permissions on bootloader config are configured"
  chown root:root /boot/grub/grub.cfg && chmod u-wx,go-rwx /boot/grub/grub.cfg
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on bootloader config are configured"
  fi
}
#######################################################################################################

#1.4.4 Ensure authentication required for single user mode (Automated)
function 1.4.4 (){
  echo -e "${RED}1.4.3${NC} Ensure authentication required for single user mode"
  passwd root
  echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"
}
#######################################################################################################

#1.5.2 Ensure address space layout randomization (ASLR) is enabled (Automated)
function 1.5.2 (){
  echo -e "${RED}1.5.3${NC} Ensure address space layout randomization (ASLR) is enabled"
  egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
  echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"
}
#######################################################################################################

#1.5.3 Ensure prelink is disabled (Automated)
function 1.5.3 (){
  echo -e "${RED}1.5.3${NC} Ensure prelink is disabled"
  apt remove prelink -y
  echo -e "${GREEN}Remediated:${NC} Ensure prelink is disabled"
}
#######################################################################################################

#1.5.4 Ensure core dumps are restricted (Automated)
function 1.5.4 (){
  echo -e "${RED}1.5.4${NC} Ensure core dumps are restricted"
  grep -i "hard core 0" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf
  grep -i "fs.suid_dumpable = 0" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
  sysctl -w fs.suid_dumpable=0
  systemctl daemon-reload
  sed -i "s/enabled=1/enabled=0/" /etc/default/apport
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure core dumps are restricted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure core dumps are restricted"
  fi
}
#######################################################################################################

#1.6.1.1 Ensure AppArmor is installed (Automated)
function 1.6.1.1 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install apparmor apparmor-utils -y
  apt autoremove -y
  systemctl start apparmor
  systemctl enable apparmor
}
#######################################################################################################

#1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
function 1.6.1.3 (){
  aa-enforce /etc/apparmor.d/*
  aa-complain /etc/apparmor.d/*
}
#######################################################################################################

#1.6.1.4 Ensure all AppArmor Profiles are enforcing (Automated)
function 1.6.1.4 (){
  aa-enforce /etc/apparmor.d/*
}
#######################################################################################################

#1.7.1 Ensure message of the day is configured properly (Automated)
function 1.7.1 (){
  echo -e "${RED}1.7.1${NC} Ensure message of the day is configured properly"
  grep -i "ENABLED=0" /etc/default/motd-news || sed -i "s/ENABLED=1/ENABLED=0/" /etc/default/motd-news
  rm -rf /etc/update-motd.d/*
  echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure remote login warning banner is configured properly"
  fi
}
#######################################################################################################

#1.7.2 Ensure permissions on /etc/issue.net are configured (Automated)
function 1.7.2 (){
  echo -e "${RED}1.7.2${NC} Ensure permissions on /etc/issue.net are configured"
  chown root:root /etc/issue.net
  chmod 644 /etc/issue.net
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"
}
#######################################################################################################

#1.7.3 Ensure permissions on /etc/issue are configured (Automated)
function 1.7.3 (){
  echo -e "${RED}1.7.3${NC} Ensure permissions on /etc/issue are configured"
  chown root:root /etc/issue
  chmod 644 /etc/issue
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"
}
#######################################################################################################

#1.7.4 Ensure permissions on /etc/motd are configured (Automated)
function 1.7.4 (){
  echo -e "${RED}1.7.4${NC} Ensure permissions on /etc/motd are configured"
  chown root:root /etc/motd && chmod u-x,go-wx /etc/motd
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/motd are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/motd are configured"
  fi
}
#######################################################################################################

#1.7.5 Ensure remote login warning banner is configured properly (Automated)
function 1.7.5 (){
  echo -e "${RED}1.7.5${NC} Ensure remote login warning banner is configured properly"
  echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
  echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"
}
#######################################################################################################

#1.7.6 Ensure local login warning banner is configured properly (Automated)
function 1.7.6 (){
  echo -e "${RED}1.7.6${NC} Ensure local login warning banner is configured properly"
  echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
  echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"
}
#######################################################################################################

#1.8.1 Ensure GNOME Display Manager is removed (Manual)
function 1.8.1 (){
  apt purge gdm3 -y
  apt autoremove -y
}
#######################################################################################################

#1.9 Ensure updates, patches, and additional security software are installed (Manual)
function 1.9 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt list --upgradable > /tmp/list_of_packages_update
}

function 1.9_2 (){
  if [ -s /tmp/list_of_packages_update ]; then 
    echo -e "${RED}this list of your packages update"
    cat /tmp/list_of_packages_update
  else 
    echo -e "${GREEN}your packages up to date"
  fi 
}
#######################################################################################################

#2.2.1.2 Ensure systemd-timesyncd is configured (Not Scored)
function 2.2.1.2 (){
  echo -e "${RED}2.2.1.2${NC} Ensure systemd-timesyncd is configured"
  systemctl enable systemd-timesyncd.service
  echo "NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 
  FallbackNTP=ntp.ubuntu.com 3.ubuntu.pool.ntp.org
  RootDistanceMaxSec=1" >> /etc/systemd/timesyncd.conf
  systemctl start systemd-timesyncd.service
  timedatectl set-ntp true
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure systemd-timesyncd is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure systemd-timesyncd is configured"
  fi
}
#######################################################################################################

#2.1.1.1 Ensure time synchronization is in use (Automated)
function 2.1.1.1 (){
  echo -e "${RED}2.1.1.1${NC} Ensure time synchronization is in use"
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install -y ntp
  apt install -y chrony
  systemctl start ntp.service
  systemctl enable ntp.service
  systemctl start chronyd.service
  systemctl enable chrony.service
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure time synchronization is in use"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure time synchronization is in use"
  fi
}
#######################################################################################################

#2.1.1.3 Ensure chrony is configured (Automated)
function 2.1.1.3 (){
  echo -e "${RED}2.1.1.3${NC} Ensure chrony is configured"
  if dpkg -s chrony 2> /dev/null 1>&2; then

          # CHRONY_FIRST_FIELD=`ps -ef | grep chronyd | head -n1 | awk '{print $1}'`
          # if [[ $CHRONY_FIRST_FIELD == "_chrony" ]]; then 
          systemctl --now mask systemd-timesyncd
          if  ! grep "user _chrony" /etc/chrony/chrony.conf 2> /dev/null 1>&2; then
              echo "user _chrony" >> /etc/chrony/chrony.conf
          fi

          while true; do
              read -p "enter chrony server address (ip or domain): " CHRONY_ADDRESS
              if domain_checker $CHRONY_ADDRESS || ip_checker $CHRONY_ADDRESS; then 
                  break;
              else 
                  echo -e "${RED}Your server address invalid${NC}"
              fi 
          done   
          
          if ! grep -E "^(server)" /etc/chrony/chrony.conf 2>/dev/null 1>&2; then 
              sed -i "/pool/d" /etc/chrony/chrony.conf
              echo "pool $CHRONY_ADDRESS iburst" >> /etc/chrony/chrony.conf 
          fi

          systemctl restart chrony.service

          CHRONY_OUT="0"
  #    else  
  #         echo -e "${RED}service Chrony is not active${NC}"
  #         CHRONY_OUT="1"
  #    fi
  else 
      CHRONY_OUT="1"
  fi

  if [[ $CHRONY_OUT == "0" ]]; then
      echo -e "${GREEN}Remediated:${NC} Ensure chrony is configured"
  else
      echo -e "${RED}UnableToRemediate:${NC} chrony is not installed"
  fi
}

#######################################################################################################

#2.1.1.4 Ensure ntp is configured (Automated)
function 2.1.1.4 (){
  echo -e "${RED}2.1.1.4${NC} Ensure ntp is configured"
  if dpkg -s ntp >/dev/null; then
      egrep -q "^\s*restrict(\s+-4)?\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict(\s+-4)?\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict\2 default kod nomodify notrap nopeer noquery\4/" /etc/ntp.conf || echo "restrict default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf 
      egrep -q "^\s*restrict\s+-6\s+default(\s+\S+)*(\s*#.*)?\s*$" /etc/ntp.conf && sed -ri "s/^(\s*)restrict\s+-6\s+default(\s+[^[:space:]#]+)*(\s+#.*)?\s*$/\1restrict -6 default kod nomodify notrap nopeer noquery\3/" /etc/ntp.conf || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf 
      egrep -q "^(\s*)OPTIONS\s*=\s*\"(([^\"]+)?-u\s[^[:space:]\"]+([^\"]+)?|([^\"]+))\"(\s*#.*)?\s*$" /etc/init.d/ntp && sed -ri '/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/ {/^(\s*)OPTIONS\s*=\s*\"[^\"]*-u\s+\S+[^\"]*\"(\s*#.*)?\s*$/! s/^(\s*)OPTIONS\s*=\s*\"([^\"]*)\"(\s*#.*)?\s*$/\1OPTIONS=\"\2 -u ntp:ntp\"\3/ }' /etc/init.d/ntp && sed -ri "s/^(\s*)OPTIONS\s*=\s*\"([^\"]+\s+)?-u\s[^[:space:]\"]+(\s+[^\"]+)?\"(\s*#.*)?\s*$/\1OPTIONS=\"\2\-u ntp:ntp\3\"\4/" /etc/init.d/ntp || echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/init.d/ntp
  fi
  echo -e "${GREEN}Remediated:${NC} Ensure ntp is configured"
}
#######################################################################################################

#2.1.2 Ensure X Window System is not installed (Automated)
function 2.1.2 (){
  echo -e "${RED}2.1.2${NC} Ensure X Window System is not installed"
  apt remove xserver-xorg* -y
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure X Window System is not installed"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure X Window System is not installed"
  fi
}
#######################################################################################################

#2.1.3 Ensure Avahi Server is not installed (Automated)
function 2.1.3 (){
  echo -e "${RED}2.1.3${NC} Ensure Avahi Server is not installed"
  systemctl disable avahi-daemon
  apt purge avahi-daemon -y
  systemctl stop avahi-daaemon.service
  systemctl stop avahi-daemon.socket
  echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not installed"
}
#######################################################################################################

#2.1.4 Ensure CUPS is not installed (Automated)
function 2.1.4 (){
  echo -e "${RED}2.1.4${NC} Ensure CUPS is not installed"
  systemctl disable cups
  apt purge cups -y
  echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not installed"
}
#######################################################################################################

#2.1.5 Ensure DHCP Server is not installed (Automated)
function 2.1.5 (){
  echo -e "${RED}2.1.5${NC} Ensure DHCP Server is not installed"
  apt purge isc-dhcp-server -y
  systemctl disable isc-dhcp-server
  systemctl disable isc-dhcp-server6
  echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not installed"
}
#######################################################################################################

#2.1.6 Ensure LDAP server is not installed (Automated)
function 2.1.6 (){
  echo -e "${RED}2.1.6${NC} Ensure LDAP server is not installed"
  apt purge slapd -y
  systemctl disable slapd
  echo -e "${GREEN}Remediated:${NC} Ensure LDAP server is not installed"
}
#######################################################################################################

#2.1.7 Ensure NFS is not installed (Automated)
function 2.1.7 (){
  echo -e "${RED}2.1.6${NC} Ensure NFS is not installed"
  apt purge nfs-kernel-server -y
  echo -e "${GREEN}Remediated:${NC} Ensure NFS is not installed"
}
#######################################################################################################

#2.1.8 Ensure DNS Server is not installed (Automated)
function 2.1.8 (){
  echo -e "${RED}2.1.8${NC} Ensure DNS Server is not installed"
  apt purge bind9 -y
  systemctl disable bind9
  echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not installed"
}
#######################################################################################################

#2.1.9 Ensure FTP Server is not installed (Automated)
function 2.1.9 (){
  echo -e "${RED}2.1.9${NC} Ensure FTP Server is not installed"
  apt purge vsftpd -y
  echo -e "${GREEN}Remediated:${NC} Ensure FTP Server is not installed"
}
#######################################################################################################

#2.1.10 Ensure HTTP server is not installed (Automated)
function 2.1.10 (){
  apt purge apache2 -y
}
#######################################################################################################

#2.1.11 Ensure IMAP and POP3 server are not installed (Automated)
function 2.1.11 (){
  apt purge dovecot-imapd dovecot-pop3d -y
}
#######################################################################################################

#2.1.12 Ensure Samba is not installed (Automated)
function 2.1.12 (){
  apt purge samba -y
}
#######################################################################################################

#2.1.13 Ensure HTTP Proxy Server is not installed (Automated)
function 2.1.13 (){
  apt purge squid -y
}
#######################################################################################################

#2.1.14 Ensure SNMP Server is not installed (Automated)
function 2.1.14 (){
  apt purge snmpd -y
}
#######################################################################################################

#2.1.16 Ensure rsync service is not installed (Automated)
function 2.1.16 (){
  apt purge rsync -y
}
#######################################################################################################

#2.1.17 Ensure NIS Server is not installed (Automated)
function 2.1.17 (){
  apt purge nis -y
}
#######################################################################################################

#2.2.1 Ensure NIS Client is not installed (Automated)
function 2.2.1 (){
  apt purge nis -y
}
#######################################################################################################

#2.2.2 Ensure rsh client is not installed (Automated)
function 2.2.2 (){
  apt purge rsh-client -y
}
#######################################################################################################

#2.2.3 Ensure talk client is not installed (Automated)
function 2.2.3 (){
  apt purge talk -y
}
#######################################################################################################

#2.2.4 Ensure telnet client is not installed (Automated)
function 2.2.4 (){
  apt purge telnet -y
}
#######################################################################################################

#2.2.5 Ensure LDAP client is not installed (Automated)
function 2.2.5 (){
  apt purge ldap-utils -y
}
#######################################################################################################

#2.2.6 Ensure RPC is not installed (Automated)
function 2.2.6 (){
  apt purge rpcbind -y
}
#######################################################################################################

#3.1.1 Disable IPv6 (Manual)
function 3.1.1 (){
  grep -i "ipv6.disable=1" /etc/default/grub || echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
  update-grub
  grep "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.conf
  grep "net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf || echo net.ipv6.conf.default.disable_ipv6 = 1 >> /etc/sysctl.conf
  grep "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.d/10-ipv6-privacy.conf || echo net.ipv6.conf.all.disable_ipv6 = 1 >> /etc/sysctl.d/10-ipv6-privacy.conf
  grep "net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.d/10-ipv6-privacy.conf || echo net.ipv6.conf.default.disable_ipv6 = 1 >> /etc/sysctl.d/10-ipv6-privacy.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Disable IPv6"
  else
    echo -e "${RED}UnableToRemediate:${NC} Disable IPv6"
  fi
}
#######################################################################################################

#3.2.1 Ensure packet redirect sending is disabled (Automated)
function 3.2.1 (){
  echo -e "${RED}3.2.1${NC} Ensure packet redirect sending is disabled"
  egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
  egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sysctl -w net.ipv4.route.flush=1
  echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"
}
#######################################################################################################

#3.2.2 Ensure IP forwarding is disabled (Automated)
function 3.2.2 (){
  echo -e "${RED}3.2.2${NC} Ensure IP forwarding is disabled"
  egrep -q "^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.ip_forward\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.ip_forward = 0\2/" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
  sysctl -w net.ipv4.ip_forward=0
  sysctl -w net.ipv4.route.flush=1
  echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"
}
#######################################################################################################

#3.3.1 Ensure source routed packets are not accepted (Automated)
function 3.3.1 (){
  echo -e "${RED}3.3.1${NC} Ensure source routed packets are not accepted"
  echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
  echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure source routed packets are not accepted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure source routed packets are not accepted"
  fi
}
#######################################################################################################

#3.3.2 Ensure ICMP redirects are not accepted (Automated)
function 3.3.2 (){
  echo -e "${RED}3.3.2${NC} Ensure ICMP redirects are not accepted"
  egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
  egrep -q "^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.default.accept_redirects=0
  sysctl -w net.ipv4.route.flush=1
  echo -e "${GREEN}Remediated:${NC} Ensure ICMP redirects are not accepted"
}
#######################################################################################################

#Ensure IPv6 redirects are not accepted (Not Scored)

function old_cis_1 () {
  grep "net.ipv6.conf.all.accept_redirects = 0" /etc/sysctl.conf || echo net.ipv6.conf.all.accept_redirects = 0 >> /etc/sysctl.conf
  grep "net.ipv6.conf.default.accept_redirects = 0" /etc/sysctl.conf || echo net.ipv6.conf.default.accept_redirects = 0 >> /etc/sysctl.conf
  grep "net.ipv6.conf.all.accept_redirects = 0" /etc/sysctl.d/10-ipv6-privacy.conf || echo net.ipv6.conf.all.accept_redirects = 0 >> /etc/sysctl.d/10-ipv6-privacy.conf
  grep "net.ipv6.conf.default.accept_redirects = 0" /etc/sysctl.d/10-ipv6-privacy.conf || echo net.ipv6.conf.default.accept_redirects = 0 >> /etc/sysctl.d/10-ipv6-privacy.conf
  sysctl -w net.ipv6.conf.all.accept_redirects=0
  sysctl -w net.ipv6.conf.default.accept_redirects=0
  sysctl -w net.ipv6.route.flush=1
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure IPv6 redirects are not accepted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 redirects are not accepted"
  fi
}

#######################################################################################################

#3.3.3 Ensure secure ICMP redirects are not accepted (Automated)
function 3.3.3 (){
  echo -e "${RED}3.3.3${NC} Ensure secure ICMP redirects are not accepted"
  egrep -q "^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
  egrep -q "^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.secure_redirects=0
  sysctl -w net.ipv4.conf.default.secure_redirects=0
  sysctl -w net.ipv4.route.flush=1
  echo -e "${GREEN}Remediated:${NC} Ensure secure ICMP redirects are not accepted"
}
#######################################################################################################

#3.3.4 Ensure suspicious packets are logged (Automated)
function 3.3.4 (){
  echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.log_martians=1
  sysctl -w net.ipv4.conf.default.log_martians=1
  sysctl -w net.ipv4.route.flush=1
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure suspicious packets are logged"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure suspicious packets are logged"
  fi
}
#######################################################################################################

#3.3.5 Ensure broadcast ICMP requests are ignored (Automated)
function 3.3.5 (){
  echo -e "${RED}3.3.5${NC} Ensure broadcast ICMP requests are ignored"
  egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
  echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"
}
#######################################################################################################

#3.3.6 Ensure bogus ICMP responses are ignored (Automated)
function 3.3.6 (){
  echo -e "${RED}3.3.6${NC} Ensure bogus ICMP responses are ignored"
  egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
  echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"
}
#######################################################################################################

#3.3.7 Ensure Reverse Path Filtering is enabled (Automated)
function 3.3.7 (){
  echo -e "${RED}3.3.7${NC} Ensure Reverse Path Filtering is enabled"
  egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
  egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
  echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"
}
#######################################################################################################

#3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
function 3.3.8 (){
  echo -e "${RED}3.3.8${NC} Ensure TCP SYN Cookies is enabled"
  egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
  echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"
}
#######################################################################################################

#3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)
function 3.3.9 (){
  echo net.ipv6.conf.all.accept_ra = 0 >> /etc/sysctl.conf
  echo net.ipv6.conf.default.accept_ra = 0 >> /etc/sysctl.conf
  sysctl -w net.ipv6.conf.all.accept_ra=0
  sysctl -w net.ipv6.conf.default.accept_ra=0
  sysctl -w net.ipv6.route.flush=1
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure IPv6 router advertisements are not accepted"
  fi
}
#echo -e "${RED}3.3.9${NC} Ensure IPv6 router advertisements are not accepted"
#egrep -q "^(\s*net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
#egrep -q "^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
#sysctl -w net.ipv6.conf.all.accept_ra=0
#sysctl -w net.ipv6.conf.default.accept_ra=0
#sysctl -w net.ipv6.route.flush=1
#echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"

#######################################################################################################

#3.4.1 Ensure DCCP is disabled (Automated)
function 3.4.1 (){
  echo -e "${RED}3.4.1${NC} Ensure DCCP is disabled"
  modprobe -n -v dccp | grep "^install /bin/true$" || echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^dccp\s" && rmmod dccp
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure DCCP is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure DCCP is disabled"
  fi
}
#######################################################################################################

#Ensure TCP Wrappers is installed  (Automated)
function 3.4.1_tcp (){
echo -e "${RED}3.4.1${NC} Ensure TCP Wrappers is installed"
apt update
rm -rf /var/lib/dpkg/lock-frontend
rm -rf /var/lib/dpkg/lock
apt-get install tcpd -y
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure TCP Wrappers is installed"
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure TCP Wrappers is installed"
fi
}

#######################################################################################################

#3.4.2 Ensure SCTP is disabled (Automated)
function 3.4.2 (){
  echo -e "${RED}3.4.2${NC} Ensure SCTP is disabled"
  modprobe -n -v sctp | grep "^install /bin/true$" || echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^sctp\s" && rmmod sctp
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SCTP is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SCTP is disabled"
  fi
}
#######################################################################################################

#3.4.3 Ensure RDS is disabled (Automated)
function 3.4.3 (){
  echo -e "${RED}3.4.3${NC} Ensure RDS is disabled"
  modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^rds\s" && rmmod rds
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure RDS is disabled"
  fi
}
#######################################################################################################

#3.4.4 Ensure TIPC is disabled (Automated)
function 3.4.4 (){
  echo -e "${RED}3.4.4${NC} Ensure TIPC is disabled"
  modprobe -n -v tipc | grep "true" || echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
  policystatus=$?
  lsmod | egrep "^tipc\s" && rmmod tipc
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure TIPC is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure TIPC is disabled"
  fi
}
#######################################################################################################

#3.5.2.3 Ensure loopback traffic is configured (Scored)
function 3.5.2.3 (){
  echo -e "${RED}3.5.2.3${NC} 3.5.2.3 Ensure loopback traffic is configured"
  ufw allow in on lo
  ufw deny in from 127.0.0.0/8
  ufw deny in from ::1
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure loopback traffic is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure loopback traffic is configured"
  fi
}
#######################################################################################################

#4.1.1.1 Ensure auditd is installed (Automated)
function 4.1.1.1 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install auditd audispd-plugins -y
  apt autoremove -y
  systemctl start auditd.service
  systemctl enable auditd.service
  systemctl daemon-reload
}
#######################################################################################################

#4.1.1.2 Ensure auditd service is enabled (Automated)
function 4.1.1.2 (){
  systemctl --now enable auditd
  systemctl enable auditd
}
#######################################################################################################

#4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated) 
function 4.1.1.3 (){
  echo -e "${RED}4.1.1.3${NC} Ensure auditing for processes that start prior to auditd is enabled"
  grep -i "audit=1" /etc/default/grub || echo GRUB_CMDLINE_LINUX="audit=1" >> /etc/default/grub
  update-grub
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure auditing for processes that start prior to auditd is enabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure auditing for processes that start prior to auditd is enabled"
  fi
}

#######################################################################################################

#4.1.1.4 Ensure audit_backlog_limit is sufficient (Scored)
function 4.1.1.4_audit (){
  echo -e "${RED}4.1.1.4${NC} Ensure audit_backlog_limit is sufficient"
  echo 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' >> /etc/default/grub
  echo 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' >> /boot/grub/grub.cfg
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure audit_backlog_limit is sufficient"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure audit_backlog_limit is sufficient"
  fi
}
#######################################################################################################

#4.1.2.1 Ensure audit log storage size is configured (Automated)
function 4.1.2.1 (){
  while true; do
      read -p "enter size of audit file (MB): " AUDIT_FILE_SIZE

      if [[ $AUDIT_FILE_SIZE -gt 0 ]]; then
          break;
      else 
          echo -e "${RED}file size invalid${NC}"
      fi 
  done   

  sed -ie 's/^max_log_file\ =\ [[:digit:]]\{1,\}/max_log_file = '$AUDIT_FILE_SIZE'/g' /etc/audit/auditd.conf
  echo -e "${GREEN}Remediated:${NC} Ensure audit log storage size is configured"
}
#######################################################################################################

#4.1.2.2 Ensure audit logs are not automatically deleted (Automated)
function 4.1.2.2 (){
  echo -e "${RED}4.1.2.2${NC} Ensure audit logs are not automatically deleted"
  egrep -q "^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$/\1max_log_file_action = keep_logs\2/" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure audit logs are not automatically deleted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure audit logs are not automatically deleted"
  fi
}
#######################################################################################################

#4.1.2.3 Ensure system is disabled when audit logs are full (Automated)
function 4.1.2.3 (){
  echo -e "${RED}4.1.2.3${NC} Ensure system is disabled when audit logs are full"
  egrep -q "^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1space_left_action = email\2/" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
  egrep -q "^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$/\1action_mail_acct = root\2/" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf
  egrep -q "^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1admin_space_left_action = halt\2/" /etc/audit/auditd.conf || echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
  echo -e "${GREEN}Remediated:${NC} Ensure system is disabled when audit logs are full"
}
#######################################################################################################

#4.1.3 Ensure events that modify date and time information are collected (Automated)
function 4.1.3 (){
  echo -e "${RED}4.1.3${NC} Ensure events that modify date and time information are collected"
  echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/50-time.rules
  echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/50-time.rules
  echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time.rules
  echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time.rules
  echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/50-time.rules
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify date and time information are collected"
}
#######################################################################################################

#4.1.4 Ensure events that modify user/group information are collected (Automated)
function 4.1.4 (){
  echo -e "${RED}4.1.4${NC} Ensure events that modify user/group information are collected"
  echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
  echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
  echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
  echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
  echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/50-user.rules
  echo -e "${GREEN}Remediated:${NC} Ensure events that modify user/group information are collected"
}
#######################################################################################################

#4.1.5 Ensure events that modify the system's network environment are collected (Automated)
function 4.1.5 (){
  read -p "Do you want to Remediat events that modify the system's network environment are collected ? (YES/NO) " REMEDIAT_EVENTS_NETWORK_INPUT
  if [[ ! ${REMEDIAT_EVENTS_NETWORK_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.5${NC} Ensure events that modify the system's network environment are collected"
    egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-network.rules
    egrep "^-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/50-network.rules
    egrep "^-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/50-network.rules
    egrep "^-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/50-network.rules
    egrep "^-w\s+/etc/network\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/50-network.rules
    uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-network.rules
    echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's network environment are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's network environment are collected"
  fi
}
#######################################################################################################

#4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)
function 4.1.6 (){
  read -p "Do you want to Remediat events that modify the system's Mandatory Access Controls are collected ? (YES/NO) " REMEDIAT_EVENTS_MAC_INPUT
  if [[ ! ${REMEDIAT_EVENTS_MAC_INPUT,,} =~ ^no$ ]]; then 
    echo -e "${RED}4.1.6${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
    echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-apparmor.rules
    echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-apparmor.rules
    echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
  fi
}
#######################################################################################################

#4.1.7 Ensure login and logout events are collected (Automated)
function 4.1.7 (){
  read -p "Do you want to Remediat login and logout events are collected ? (YES/NO) " REMEDIAT_LOGIN_INPUT
  if [[ ! ${REMEDIAT_LOGIN_INPUT,,} =~ ^no$ ]]; then 
    echo -e "${RED}4.1.7${NC} Ensure login and logout events are collected"
    echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
    echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
    echo -e "${GREEN}Remediated:${NC} Ensure login and logout events are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure login and logout events are collected"
  fi
}
#######################################################################################################

#4.1.8 Ensure session initiation information is collected (Automated)
function 4.1.8 (){
  read -p "Do you want to Remediat session initiation information is collected ? (YES/NO) " REMEDIAT_SESSION_INITIATION_INPUT
  if [[ ! ${REMEDIAT_SESSION_INITIATION_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.8${NC} Ensure session initiation information is collected"
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/50-session.rules
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules
    echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules
    echo -e "${GREEN}Remediated:${NC} Ensure session initiation information is collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure session initiation information is collected"
  fi
}
#######################################################################################################

#4.1.9 Ensure discretionary access control permission modification events are collected (Automated)
function 4.1.9 (){
  read -p "Do you want to Remediat discretionary access control permission modification events are collected ? (YES/NO) " REMEDIAT_DISCRETTIONARY_ACCESS_INPUT
  if [[ ! ${REMEDIAT_DISCRETTIONARY_ACCESS_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.9${NC} Ensure discretionary access control permission modification events are collected"
    egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
    echo -e "${GREEN}Remediated:${NC} Ensure discretionary access control permission modification events are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure discretionary access control permission modification events are collected"
  fi
}
#######################################################################################################

#4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)
function 4.1.10 (){
  read -p "Do you want to Remediat unsuccessful unauthorized file access attempts are collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.10${NC} Ensure unsuccessful unauthorized file access attempts are collected"
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
    echo -e "${GREEN}Remediated:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure unsuccessful unauthorized file access attempts are collected"
  fi
}
#######################################################################################################

#4.1.11 Ensure use of privileged commands is collected (Automated)
function 4.1.11 (){
  read -p "Do you want to Remediat use of privileged commands is collected ? (YES/NO) " REMEDIAT_PRIVILEDGED_COMMAND_INPUT
    if [[ ! ${REMEDIAT_PRIVILEDGED_COMMAND_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.11${NC} Ensure use of privileged commands is collected"
    for file in `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`; do
        egrep -q "^\s*-a\s+(always,exit|exit,always)\s+-F\s+path=$file\s+-F\s+perm=x\s+-F\s+auid>=500\s+-F\s+auid!=4294967295\s+-k\s+privileged\s*(#.*)?$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=$file -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/50-privileged-commands.rules;
    done
    systemctl restart auditd.service
    policystatus=$?
    if [[ "$policystatus" -eq 0 ]]; then
      echo -e "${GREEN}Remediated:${NC} Ensure use of privileged commands is collected"
    else
      echo -e "${RED}UnableToRemediate:${NC} Ensure use of privileged commands is collected"
    fi
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure use of privileged commands is collected"
  fi
}
#######################################################################################################

#4.1.12 Ensure successful file system mounts are collected (Automated)
function 4.1.12 (){
  read -p "Do you want to remediat successful file system mounts are collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.12${NC} Ensure successful file system mounts are collected"
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/50-mounts.rules
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/50-mounts.rules
    echo -e "${GREEN}Remediated:${NC} Ensure successful file system mounts are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure successful file system mounts are collected"
  fi
}
#######################################################################################################

#4.1.13 Ensure file deletion events by users are collected (Automated)
function 4.1.13 (){
  read -p "Do you want to remediat file deletion events by users are collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.13${NC} Ensure file deletion events by users are collected"
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/50-delete.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/50-delete.rules
    echo -e "${GREEN}Remediated:${NC} Ensure file deletion events by users are collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure file deletion events by users are collected"
  fi
}
#######################################################################################################

#4.1.14 Ensure changes to system administration scope (sudoers) is collected (Automated)
function 4.1.14 (){
  read -p "Do you want to remediat changes to system administration scope (sudoers) is collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.14${NC} Ensure changes to system administration scope (sudoers) is collected"
    echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules
    echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules
    echo -e "${GREEN}Remediated:${NC} Ensure changes to system administration scope (sudoers) is collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure changes to system administration scope (sudoers) is collected"
  fi  
}
#######################################################################################################

#4.1.15 Ensure system administrator actions (sudolog) are collected (Scored)
#function 4.1.15 (){
#  read -p "Do you want to remediat system administrator actions (sudolog) are collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
#  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
#    echo -e "${RED}4.1.15${NC} Ensure system administrator actions (sudolog) are collected"
#    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/50-actions.rules
#    echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"
#  else 
#    echo -e "${RED}UnableToRemediate:${NC} Ensure system administrator actions (sudolog) are collected"
#  fi
#}

#######################################################################################################

#4.1.15 Ensure system administrator command executions (sudo) are collected (Automated)
 function 4.1.15_sudo (){
   echo -e "${RED}4.1.15${NC} Ensure system administrator actions (sudolog) are collected"
   echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=500 -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/50-actions.rules
   echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=500 -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/50-actions.rules
   policystatus=$?
   if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"
   else
    echo -e "${RED}UnableToRemediate:${NC} Ensure system administrator actions (sudolog) are collected"
   fi
 }

#######################################################################################################

#4.1.16 Ensure kernel module loading and unloading is collected (Automated)
function 4.1.16 (){
  read -p "Do you want to remediat kernel module loading and unloading is collected ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.16${NC} Ensure kernel module loading and unloading is collected"
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/50-kernel.rules
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/50-kernel.rules
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/50-kernel.rules
    echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-kernel.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-kernel.rules
    echo -e "${GREEN}Remediated:${NC} Ensure kernel module loading and unloading is collected"
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure kernel module loading and unloading is collected"
  fi
}
#######################################################################################################

#4.1.17 Ensure the audit configuration is immutable (Automated)
function 4.1.17 (){
  read -p "Do you want to remediat the audit configuration is immutable ? (YES/NO) " REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT
  if [[ ! ${REMEDIAT_UNSUCCESSFUL_UNAUTHORIZED_INPUT,,} =~ ^no$ ]]; then
    echo -e "${RED}4.1.17${NC} Ensure the audit configuration is immutable"
    grep "-e 2" /etc/audit/rules.d/*.rules || echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules 
    echo -e "${GREEN}Remediated:${NC} Ensure the audit configuration is immutable"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure the audit configuration is immutable"
  fi
}
#######################################################################################################

#4.2.1.1 Ensure rsyslog is installed (Automated)
function 4.2.1.1 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install rsyslog -y
  apt autoremove -y
}
#######################################################################################################

#4.2.1.2 Ensure rsyslog Service is enabled (Automated)
function 4.2.1.2 (){
  systemctl --now enable rsyslog
  systemctl enable rsyslog
}
#######################################################################################################

#4.2.1.3 Ensure logging is configured
function 4.2.1.3 (){
  if dpkg -s rsyslog 2>/dev/null 1>&2; then 
      # check rsyslog service to be active
      if ! systemctl is-enabled rsyslog 2>/dev/null 1>&2; then 
          systemctl --now enable rsyslog
      fi
  else 
      apt install -y rsyslog
      systemctl --now enable rsyslog
  fi

  # update config
  echo '*.emerg :omusrmsg:' >> /etc/rsyslog.d/50-default.conf
  echo 'auth,authpriv.* /var/log/auth.log' >> /etc/rsyslog.d/50-default.conf
  echo 'mail.* -/var/log/mail' >> /etc/rsyslog.d/50-default.conf
  echo 'mail.info -/var/log/mail.info' >> /etc/rsyslog.d/50-default.conf
  echo 'mail.warning -/var/log/mail.warn' >> /etc/rsyslog.d/50-default.conf
  echo 'mail.err /var/log/mail.err' >> /etc/rsyslog.d/50-default.conf
  echo 'news.crit -/var/log/news/news.crit' >> /etc/rsyslog.d/50-default.conf
  echo 'news.err -/var/log/news/news.err' >> /etc/rsyslog.d/50-default.conf
  echo 'news.notice -/var/log/news/news.notice' >> /etc/rsyslog.d/50-default.conf
  echo '*.=warning;*.=err -/var/log/warn' >> /etc/rsyslog.d/50-default.conf
  echo '*.crit /var/log/warn' >> /etc/rsyslog.d/50-default.conf
  echo '*.*;mail.none;news.none -/var/log/messages' >> /etc/rsyslog.d/50-default.conf
  echo 'local0,local1.* -/var/log/localmessages' >> /etc/rsyslog.d/50-default.conf
  echo 'local2,local3.* -/var/log/localmessages' >> /etc/rsyslog.d/50-default.conf
  echo 'local4,local5.* -/var/log/localmessages' >> /etc/rsyslog.d/50-default.conf
  echo 'local6,local7.* -/var/log/localmessages' >> /etc/rsyslog.d/50-default.conf
  echo '*.*;auth,authpriv.none -/var/log/syslog' >> /etc/rsyslog.d/50-default.conf
  echo 'kern.* -/var/log/kern.log' >> /etc/rsyslog.d/50-default.conf

  systemctl reload rsyslog

  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"
}

#######################################################################################################

#4.2.1.4 Ensure rsyslog default file permissions configured (Automated)
function 4.2.1.4 (){
  echo -e "${RED}4.2.1.4${NC} Ensure rsyslog default file permissions configured"
  grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
  grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
  echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"
}
#######################################################################################################

#4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Manual)
function 4.2.1.6 (){
  echo -e "${RED}4.2.1.6${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
  sed -i -e 's/$ModLoad imtcp.so/#$ModLoad imtcp.so/g' /etc/rsyslog.conf
  grep "$ModLoad imtcp.so" /etc/rsyslog.conf || echo "#$""ModLoad imtcp.so" >> /etc/rsyslog.conf
  sed -i -e 's/$InputTCPServerRun 514/#$InputTCPServerRun 514/g' /etc/rsyslog.conf
  grep "$InputTCPServerRun 514" /etc/rsyslog.conf || echo "#$""InputTCPServerRun 514" >> /etc/rsyslog.conf
  echo -e "${GREEN}Remediated:${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
}
#######################################################################################################

#4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
function 4.2.2.1 (){
  echo -e "${RED}4.2.2.1${NC} Ensure journald is configured to send logs to rsyslog"
  echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to send logs to rsyslog"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure journald is configured to send logs to rsyslog"
  fi
}
#######################################################################################################

#4.2.2.2 Ensure journald is configured to compress large log files (Scored)
function 4.2.2.2 (){
  echo -e "${RED}4.2.2.2${NC} Ensure journald is configured to compress large log files"
  echo "Compress=yes" >> /etc/systemd/journald.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to compress large log files"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure journald is configured to compress large log files"
  fi
}
#######################################################################################################

#4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)
function 4.2.2.3 (){
  echo -e "${RED}4.2.2.3${NC} Ensure journald is configured to write logfiles to persistent disk"
  echo "Storage=persistent" >> /etc/systemd/journald.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to write logfiles to persistent disk"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure journald is configured to write logfiles to persistent disk"
  fi
}

#######################################################################################################

#4.4 Ensure logrotate assigns appropriate permissions (Automated)
function 4.4 (){
  echo -e "${RED}4.4${NC} Ensure logrotate assigns appropriate permissions"
  sed -i "s/create 0664 root utmp/create 0640 root utmp/g" /etc/logrotate.conf
  sed -i "s/create 0664 root utmp/create 0640 root utmp/g" /etc/logrotate.conf
  sed -i "s/create 0660 root utmp/create 0640 root utmp/g" /etc/logrotate.conf
  sed -i "s/create 644 root root/create 640 root root/g" /etc/logrotate.d/alternatives
  sed -i "s/create 644 root root/create 640 root root/g" /etc/logrotate.d/dpkg
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure logrotate assigns appropriate permissions"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure logrotate assigns appropriate permissions"
  fi
}

#######################################################################################################

#5.1.1 Ensure cron daemon is enabled and running (Automated)
function 5.1.1 (){
  echo -e "${RED}5.1.1${NC} Ensure cron daemon is enabled and running"
  systemctl enable cron
  echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled and running"
}
#######################################################################################################

#5.1.2 Ensure permissions on /etc/crontab are configured (Automated)
function 5.1.2 (){
  echo -e "${RED}5.1.2${NC} Ensure permissions on /etc/crontab are configured"
  chown root:root /etc/crontab && chmod og-rwx /etc/crontab
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/crontab are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/crontab are configured"
  fi
}
#######################################################################################################

#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)
function 5.1.3 (){
  echo -e "${RED}5.1.3${NC} Ensure permissions on /etc/cron.hourly are configured"
  chown root:root /etc/cron.hourly && chmod og-rwx /etc/cron.hourly
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.hourly are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.hourly are configured"
  fi
}
#######################################################################################################

#5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)
function 5.1.4 (){
  echo -e "${RED}5.1.4${NC} Ensure permissions on /etc/cron.daily are configured"
  chown root:root /etc/cron.daily && chmod og-rwx /etc/cron.daily
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.daily are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.daily are configured"
  fi
}
#######################################################################################################

#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)
function 5.1.5 (){
  echo -e "${RED}5.1.5${NC} Ensure permissions on /etc/cron.weekly are configured"
  chown root:root /etc/cron.weekly && chmod og-rwx /etc/cron.weekly
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.weekly are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.weekly are configured"
  fi
}
#######################################################################################################

#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)
function 5.1.6 (){
  echo -e "${RED}5.1.6${NC} Ensure permissions on /etc/cron.monthly are configured"
  chown root:root /etc/cron.monthly && chmod og-rwx /etc/cron.monthly
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.monthly are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.monthly are configured"
  fi
}
#######################################################################################################

#5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)
function 5.1.7 (){
  echo -e "${RED}5.1.7${NC} Ensure permissions on /etc/cron.d are configured"
  chown root:root /etc/cron.d && chmod og-rwx /etc/cron.d
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.d are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/cron.d are configured"
  fi
}
#######################################################################################################

#5.2.1 Ensure sudo is installed (Automated)
function 5.2.1 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install sudo -y
}
#######################################################################################################

#5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)
function 5.3.1 (){
  echo -e "${RED}5.3.1${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
  fi
}
#######################################################################################################

#Ensure SSH Protocol is set to 2 (Scored)
function ssh_protocol (){
  grep -i "Protocol 2" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH Protocol is set to 2"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH Protocol is set to 2"
  fi
}
#######################################################################################################

#5.3.2 Ensure permissions on SSH private host key files are configured (Automated)
function 5.3.2 (){
  find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
  find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
}
#######################################################################################################

#5.3.3 Ensure permissions on SSH public host key files are configured (Automated)
function 5.3.3 (){
  find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
  find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
}
#######################################################################################################

#5.3.4 Ensure SSH access is limited (Automated)  - new1
function 5.3.4 (){
  if [ -f /tmp/ssh_access_deny ]; then 
    rm --force /tmp/ssh_access_deny
  fi 

  if ! sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Ei  '^\s*(allow|deny)(users|groups)\s+\S+'; then
    # get list of users + groups
    grep -w "\/bin\/bash\|sh\|zsh\|ksh\|ash" /etc/passwd | cut -d: -f1,4 > /tmp/users_groups
    echo -e ================
    echo "users list"
    echo ----------------
    for USER in $(cat /tmp/users_groups); do
      USERNAME=`echo $USER | cut -d: -f1`
      echo "$USERNAME"
    done

    read -p "Enter regular users for allow them to connect (separated by space) ? " -r -a SSH_ACCESS_USERS
    if [[ $SSH_ACCESS_USERS != "" ]]; then 
      for SSH_ACCESS_USER in "${SSH_ACCESS_USERS[@]}"; do 
          if grep -sq $SSH_ACCESS_USER /etc/passwd; then 
              echo $SSH_ACCESS_USER >> /tmp/ssh_access_deny
          fi 
      done 

      echo AllowUsers $(cat /tmp/ssh_access_deny) >> /etc/ssh/sshd_config
      systemctl restart ssh
      echo -e "${GREEN}Remediated:${NC} Ensure SSH access is limited"
    else 
      echo -e "${RED}Users Does Not Exist${NC}"
      echo -e "${RED}UnableToRemediate:${NC} Ensure SSH access is limited"
    fi         
  else 
    echo -e "${GREEN}Remediated:${NC} Ensure SSH access is limited"
  fi
}
#######################################################################################################

#5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
function 5.2.21 (){
  echo -e "${RED}5.2.21${NC} Ensure SSH AllowTcpForwarding is disabled"
  echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH AllowTcpForwarding is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH AllowTcpForwarding is disabled"
  fi
}
#######################################################################################################

#5.2.22 Ensure SSH MaxStartups is configured (Scored)
function 5.2.22 (){
  echo -e "${RED}5.2.22${NC} Ensure SSH MaxStartups is configured"
  echo "maxstartups 10:30:60" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxStartups is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxStartups is configured"
  fi
}
#######################################################################################################

#5.2.23 Ensure SSH MaxSessions is set to 4 or less (Scored)
function 5.2.23 (){
  echo -e "${RED}5.2.22${NC} Ensure SSH MaxSessions is set to 4 or less"
  echo "MaxSessions 4" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxSessions is set to 4 or less"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxSessions is set to 4 or less"
  fi
}

#######################################################################################################

#5.3.5 Ensure SSH LogLevel is appropriate (Automated)
function 5.3.5 (){
  echo -e "${RED}5.3.5${NC} Ensure SSH LogLevel is appropriate"
  egrep -q "^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LogLevel\s+\S+(\s*#.*)?\s*$/\1LogLevel INFO\2/" /etc/ssh/sshd_config || echo "LogLevel INFO" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is appropriate"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LogLevel is appropriate"
  fi
}
#######################################################################################################

#5.3.6 Ensure SSH X11 forwarding is disabled (Automated)
function 5.3.6 (){
  echo -e "${RED}5.3.6${NC} Ensure SSH X11 forwarding is disabled"
  egrep -q "^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$/\1X11Forwarding no\2/" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH X11 forwarding is disabled"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH X11 forwarding is disabled"
  fi
}
#######################################################################################################

#5.3.7 Ensure SSH MaxAuthTries is set to 4 or less (Automated)
function 5.3.7 (){
  echo -e "${RED}5.3.7${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  egrep -q "^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MaxAuthTries\s+\S+(\s*#.*)?\s*$/\1MaxAuthTries 4\2/" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH MaxAuthTries is set to 4 or less"
  fi
}
#######################################################################################################

#5.3.8 Ensure SSH IgnoreRhosts is enabled (Automated)
function 5.3.8 (){
  echo -e "${RED}5.3.8${NC} Ensure SSH IgnoreRhosts is enabled"
  egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
}
#######################################################################################################

#5.3.9 Ensure SSH HostbasedAuthentication is disabled (Automated)
function 5.3.9 (){
  echo -e "${RED}5.3.9${NC} Ensure SSH HostbasedAuthentication is disabled"
  egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
}
#######################################################################################################

#5.3.10 Ensure SSH root login is disabled (Automated)
function 5.3.10 (){
  #echo -e "${RED}5.3.10${NC} Ensure SSH root login is disabled"
  #egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  #policystatus=$?
  #if [[ "$policystatus" -eq 0 ]]; then
  #  echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
  #else
  #  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
  #fi

  # check exist regular users
  if grep bash /etc/passwd | grep -sqv root; then 
      if sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin ||  grep -Ei '^\s*PermitRootLogin\s+yes|without-password|prohibit-password' /etc/ssh/sshd_config; then 
          sed -ie "s@^PermitRootLogin [[:alpha:]].*@PermitRootLogin no@g" /etc/ssh/sshd_config
          systemctl restart ssh
      fi
  
      echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
  else 
      echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
  fi
}

#######################################################################################################

#5.3.11 Ensure SSH PermitEmptyPasswords is disabled (Automated)
function 5.3.11 (){
  echo -e "${RED}5.3.11${NC} Ensure SSH PermitEmptyPasswords is disabled"
  egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
  echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
}

#######################################################################################################

#5.3.12 Ensure SSH PermitUserEnvironment is disabled (Automated)
function 5.3.12 (){
  echo -e "${RED}5.3.12${NC} Ensure SSH PermitUserEnvironment is disabled"
  egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"
}
#######################################################################################################

#5.2.13 Ensure only strong Ciphers are used (Scored)
function 5.2.13 (){
  echo -e "${RED}5.2.13${NC} Ensure only strong Ciphers are used"
  echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure only strong Ciphers are used"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure only strong Ciphers are used"
  fi
}
#######################################################################################################

#5.3.14 Ensure only strong MAC algorithms are used (Automated)
function 5.3.14 (){
  echo -e "${RED}5.3.14${NC} Ensure only approved MAC algorithms are used"
  echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure only approved MAC algorithms are used"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure only approved MAC algorithms are used"
  fi
}

#######################################################################################################

#5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
function 5.2.15 (){
  echo -e "${RED}5.2.15${NC} Ensure only strong Key Exchange algorithms are used"
  echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure only strong Key Exchange algorithms are used"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure only strong Key Exchange algorithms are used"
  fi
}

#######################################################################################################

#5.3.16 Ensure SSH Idle Timeout Interval is configured (Automated)
function 5.3.16 (){
  echo -e "${RED}5.3.16${NC} Ensure SSH Idle Timeout Interval is configured"
  egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
  egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 0\2/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
  echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"
}
#######################################################################################################

#5.3.17 Ensure SSH LoginGraceTime is set to one minute or less (Automated)
function 5.3.17 (){
  echo -e "${RED}5.2.13${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  fi
}
#######################################################################################################

#5.3.18 Ensure SSH warning banner is configured (Automated)
function 5.3.18 (){
  echo -e "${RED}5.3.18${NC} Ensure SSH warning banner is configured"
  egrep -q "^(\s*)Banner\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)Banner\s+\S+(\s*#.*)?\s*$/\1Banner /etc/issue.net\2/" /etc/ssh/sshd_config || echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure SSH warning banner is configured"
  fi
}
#######################################################################################################

#5.4.1 Ensure password creation requirements are configured (Automated)
function 5.4.1 (){
  echo -e "${RED}5.4.1${NC} Ensure password creation requirements are configured"
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt-get install libpam-pwquality -y
  apt autoremove -y
  echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
  echo "minlen = 14" >> /etc/security/pwquality.conf
  echo "dcredit = -1" >> /etc/security/pwquality.conf
  echo "ucredit = -1" >> /etc/security/pwquality.conf
  echo "ocredit = -1" >> /etc/security/pwquality.conf
  echo "lcredit = -1" >> /etc/security/pwquality.conf
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure password creation requirements are configured"
  fi
}
#######################################################################################################

#5.4.1.2 Ensure minimum days between password changes is 7 or more
function 5.4.1.2 (){
  echo -e "${RED}1.7.1${NC} Ensure minimum days between password changes is 7 or more"
  sed -i "s/PASS_MIN_DAYS/#PASS_MIN_DAYS/g" /etc/login.defs
  echo "PASS_MIN_DAYS    7" >> /etc/login.defs
  chage --mindays 7 root
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure minimum days between password changes is 7 or more"
  fi
}
#######################################################################################################

#5.3.2 Ensure lockout for failed password attempts is configured (Scored)
function 5.3.2_lockout (){
  echo -e "${RED}5.4.3${NC} Ensure lockout for failed password attempts is configured"
  grep -i unlock_time=900 /etc/pam.d/common-auth || echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
  sed -i 's/pam_permit.so/pam_tally2.so/g' /etc/pam.d/common-account
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure lockout for failed password attempts is configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure lockout for failed password attempts is configured"
  fi
}
#######################################################################################################

#5.4.3 Ensure password reuse is limited (Automated)
function 5.4.3 (){
  echo -e "${RED}5.4.3${NC} Ensure password reuse is limited"
  echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure password reuse is limited"
  fi
}
#######################################################################################################

#5.4.4 Ensure password hashing algorithm is SHA-512 (Automated)
function 5.4.4 (){
  echo -e "${RED}5.4.4${NC} Ensure password hashing algorithm is SHA-512"
  egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/password-auth
  egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/system-auth
  echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
}
#######################################################################################################

#5.5.1.1 Ensure minimum days between password changes is configured (Automated)
function 5.5.1.1 (){
  echo -e "${RED}5.5.1.1${NC} Ensure minimum days between password changes is configured"
  egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 1\2/" /etc/login.defs || echo "PASS_MIN_DAYS 1" >> /etc/login.defs
  getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 1
  echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is configured"
}
#######################################################################################################

#5.5.1.2 Ensure password expiration is 365 days or less (Automated)
function 5.5.1.2 (){
  echo -e "${RED}5.5.1.2${NC} Ensure password expiration is 365 days or less"
  egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs
  getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"
}
#######################################################################################################

#5.5.1.3 Ensure password expiration warning days is 7 or more (Automated)
function 5.5.1.3 (){
  echo -e "${RED}5.5.1.3${NC} Ensure password expiration warning days is 7 or more"
  egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs
  getent passwd | cut -f1 -d ":" | xargs -n1 chage --warndays 7
  echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
}
#######################################################################################################

#5.5.1.4 Ensure inactive password lock is 30 days or less (Automated)
function 5.5.1.4 (){
  echo -e "${RED}5.5.1.4${NC} Ensure inactive password lock is 30 days or less"
  useradd -D -f 30 && getent passwd | cut -f1 -d ":" | xargs -n1 chage --inactive 30
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure inactive password lock is 30 days or less"
  fi
}
#######################################################################################################

#5.4.1.5 Ensure all users last password change date is in the past (Scored)
function 5.4.1.5 (){
  for usr in $(cut -d: -f1 < /etc/shadow); do
    now=$(($(date +%s) / 86400))
    change_date=$(chage --list "$usr" | grep 'Last password change' | cut -d: -f2 | awk '{$1=$1};1')

    if [[ $change_date != "never" ]]; then
      epoch_change_date=$(($(date -d "${change_date}" +%s) / 86400));
    else
      epoch_change_date='Never'
    fi

    if [[ $epoch_change_date -ge $now ]]; then
      a=`date +%Y`
      b=$((a-1970))
      time=$((b*365))

      chage -d "$time" $usr
    fi
  done
  
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure all users last password change date is in the past"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure all users last password change date is in the past" 
  fi
}
#######################################################################################################

#5.5.2 Ensure system accounts are secured (Automated)
function 5.5.2 (){
  echo -e "${RED}5.5.2${NC} Ensure system accounts are secured"
  for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
    if [ $user != "root" ]; then
      usermod -L $user
      if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
        usermod -s /usr/sbin/nologin $user
      fi
    fi
  done
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure system accounts are secured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure system accounts are secured"
  fi
}
#######################################################################################################

#5.5.3 Ensure default group for the root account is GID 0 (Automated)
function 5.5.3 (){
  echo -e "${RED}5.5.3${NC} Ensure default group for the root account is GID 0"
  usermod -g 0 root
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure default group for the root account is GID 0"
  fi
}
#######################################################################################################

#5.5.4 Ensure default user umask is 027 or more restrictive (Automated)
function 5.5.4 (){
  echo -e "${RED}5.5.4${NC} Ensure default user umask is 027 or more restrictive"
  egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bash.bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 027\2/" /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc
  egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 027\2/" /etc/profile || echo "umask 027" >> /etc/profile
  #egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile.d/*.sh || echo "umask 077" >> /etc/profile.d/*.sh
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure default user umask is 027 or more restrictive"
  fi
}
#######################################################################################################

#5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)
function 5.5.5 (){
  echo -e "${RED}5.5.5${NC} Ensure default user shell timeout is 900 seconds or less"
  egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/bash.bashrc && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/bash.bashrc || echo "TMOUT=600" >> /etc/bash.bashrc
  egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile || echo "TMOUT=600" >> /etc/profile
  egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile.d/*.sh || echo "TMOUT=600" >> /etc/profile.d/*.sh
  echo -e "${GREEN}Remediated:${NC} Ensure default user shell timeout is 900 seconds or less"
}
#######################################################################################################

#5.6 Ensure access to the su command is restricted (Scored)
function 5.6 (){
  echo -e "${RED}5.6${NC} Ensure access to the su command is restricted"
  groupadd sugroup
  echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure access to the su command is restricted"
  fi
}
#######################################################################################################

#6.1.2 Ensure permissions on /etc/passwd are configured (Automated)
function 6.1.2 (){
  echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
  chown root:root /etc/passwd
  chmod 644 /etc/passwd
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
}
#######################################################################################################

#6.1.3 Ensure permissions on /etc/passwd- are configured
function 6.1.3 (){
  echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/passwd- are configured"
  chown root:root /etc/passwd- && chmod u-x,go-rwx /etc/passwd-
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are configured"
  fi
}
#######################################################################################################

#6.1.4 Ensure permissions on /etc/group are configured
function 6.1.4 (){
  echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
  chown root:root /etc/group
  chmod 644 /etc/group
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
}
#######################################################################################################

#6.1.5 Ensure permissions on /etc/group- are configured
function 6.1.5 (){
  echo -e "${RED}6.1.5${NC} Ensure permissions on /etc/group- are configured"
  chown root:root /etc/group- && chmod u-x,go-wx /etc/group-
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group- are configured"
  fi
}
#######################################################################################################

#6.1.6 Ensure permissions on /etc/shadow are configured
function 6.1.6 (){
  echo -e "${RED}6.1.6${NC} Ensure permissions on /etc/shadow are configured"
  chown root:shadow /etc/shadow && chmod u-x,g-wx,o-rwx /etc/shadow
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
}
#######################################################################################################

#6.1.7 Ensure permissions on /etc/shadow- are configured
function 6.1.7 (){
  echo -e "${RED}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
  chown root:shadow /etc/shadow- && chmod u-x,go-rwx /etc/shadow-
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are configured"
  fi
}
#######################################################################################################

#6.1.8 Ensure permissions on /etc/gshadow are configured
function 6.1.8 (){
  echo -e "${RED}6.1.8${NC} Ensure permissions on /etc/gshadow are configured"
  chown root:shadow /etc/gshadow && chmod o-rwx,g-rw /etc/gshadow
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are configured"
  fi
}
#######################################################################################################

#6.1.9 Ensure permissions on /etc/gshadow- are configured
function 6.1.9 (){
  echo -e "${RED}6.1.9${NC} Ensure permissions on /etc/gshadow- are configured"
  chown root:shadow /etc/gshadow- && chmod o-rwx,g-rw /etc/gshadow-
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow- are configured"
  fi
}
#######################################################################################################

#6.1.11 Ensure no unowned files or directories exist
function 6.1.11 (){
  find / -xdev -nouser -exec chown root.root {} \;
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure no unowned files or directories exist"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure no unowned files or directories exist"
  fi
}
#######################################################################################################

#6.1.12 Ensure no ungrouped files or directories exist
function 6.1.12 (){
  find / -xdev -nogroup -exec chown .root {} \;
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure no ungrouped files or directories exist"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure no ungrouped files or directories exist"
  fi
}
#######################################################################################################

#6.2.1 Ensure accounts in /etc/passwd use shadowed passwords
function 6.2.1 (){
  sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
}
#######################################################################################################

#6.2.8 Ensure users' home directories permissions are 750 or more restrictive
function 6.2.8 (){
  echo -e "${RED}6.2.8${NC} Ensure users' home directories permissions are 750 or more restrictive"
  cd /home
  chmod 700 *
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure users' home directories permissions are 750 or more restrictive"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure users' home directories permissions are 750 or more restrictive"
  fi
}
#######################################################################################################

#6.2.12 Ensure root PATH Integrity (Automated)
function 6.2.12 (){
  echo -e "${RED}6.2.12${NC} Ensure root PATH Integrity (Automated)"
  local RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
  for SUB_PATH in $(echo "$RPCV" | tr ":" " "); do
    if [ -d "$SUB_PATH" ]; then
      if [[ ! $SUB_PATH =~ '/.' ]] || [[ ! $SUB_PATH =~ '$' ]]; then 
        TOTAL_PATH+=":${SUB_PATH}" 
        chown root:root -R $SUB_PATH 
        chmod 755:755 -R $SUB_PATH 
      fi
    else
      #$SUB_PATH is not a directory"
      mkdir -p $SUB_PATH
    fi
  done
  export PATH=$(echo $TOTAL_PATH | sed 's@:@@')
  echo $PATH >> ~/.bashrc 

  echo -e "${GREEN}Remediated:${NC} Ensure root PATH Integrity"
}

#######################################################################################################

#5.1.8 Ensure at/cron is restricted to authorized users (Scored)
function 5.1.8 (){
  echo -e "${RED}5.1.8${NC} Ensure at/cron is restricted to authorized users"
  rm /etc/cron.deny
  rm /etc/at.deny
  touch /etc/cron.allow
  touch /etc/at.allow
  chmod o-rwx /etc/cron.allow
  chmod g-wx /etc/cron.allow
  chmod o-rwx /etc/at.allow
  chmod g-wx /etc/at.allow
  chown root:root /etc/cron.allow
  chown root:root /etc/at.allow
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure at/cron is restricted to authorized users"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure at/cron is restricted to authorized users"
  fi
}
#######################################################################################################

#3.3.2 Ensure /etc/hosts.allow is configured
function 3.3.2_etc (){
  if [ -f /tmp/allow_source_addresses ]; then 
    rm --force /tmp/allow_source_addresses
  fi 

  read -p "enter source addresses for allow to connect ip or domain(separated by space like example.com 192.168.1.1 192.168.1.0/24): " -r -a ALLOW_SOURCE_ADDRESSES
  for ALLOW_SOURCE_ADDRESS in "${ALLOW_SOURCE_ADDRESSES[@]}"; do 
    if domain_checker $ALLOW_SOURCE_ADDRESS; then 
      echo $ALLOW_SOURCE_ADDRESS >> /tmp/allow_source_addresses
    else 
      local ADDRESS=`echo $ALLOW_SOURCE_ADDRESS | awk -F"/" '{print $1}'`
      local SUBNET=`echo $ALLOW_SOURCE_ADDRESS | awk -F"/" '{print $2}'` 
      if ip_checker $ADDRESS && ip_checker $SUBNET; then 
        echo $ALLOW_SOURCE_ADDRESS >> /tmp/allow_source_addresses
      elif ip_checker $ADDRESS; then 
        echo $ADDRESS/255.255.255.255 >> /tmp/allow_source_addresses
      fi 
    fi 
  done   

  echo ALL: $(cat /tmp/allow_source_addresses) >> /etc/hosts.allow
  echo -e "${GREEN}Remediated:${NC} Ensure hosts.allow is configured"
}
#######################################################################################################

#3.3.3 Ensure /etc/hosts.deny is configured
function 3.3.3_etc (){
  # echo "ALL: ALL" >> /etc/hosts.deny
  # echo -e "${GREEN}Remediated:${NC} Ensure hosts.deny is configured"
  read -p "Do you want to Remediat Ensure hosts.deny is configured ? (YES/NO) " HOST_DENY_REMEDIAT
  if [[ ! ${HOST_DENY_REMEDIAT,,} =~ ^no$ ]]; then
    if [ -f /tmp/deny_source_addresses ]; then 
      rm --force /tmp/deny_source_addresses
    fi 

    read -p "enter source addresses for deny from connect ip or domain(separated by space like example.com 192.168.1.1 192.168.1.0/24): " -r -a DENY_SOURCE_ADDRESSES
    for DENY_SOURCE_ADDRESS in "${DENY_SOURCE_ADDRESSES[@]}"; do 
      if domain_checker $DENY_SOURCE_ADDRESS; then 
        echo $DENY_SOURCE_ADDRESS >> /tmp/deny_source_addresses
      else 
        local ADDRESS=`echo $DENY_SOURCE_ADDRESS | awk -F"/" '{print $1}'`
        local SUBNET=`echo $DENY_SOURCE_ADDRESS | awk -F"/" '{print $2}'` 
        if ip_checker $ADDRESS && ip_checker $SUBNET; then 
          echo $DENY_SOURCE_ADDRESS >> /tmp/deny_source_addresses
        elif ip_checker $ADDRESS; then 
          echo $ADDRESS/255.255.255.255 >> /tmp/deny_source_addresses
        fi 
      fi 
    done 

    echo ALL: $(cat /tmp/deny_source_addresses) >> /etc/hosts.deny
    echo -e "${GREEN}Remediated:${NC} Ensure hosts.deny is configured"  
  else 
    echo -e "${RED}UnableToRemediate:${NC} Ensure hosts.deny is configured"
  fi 
}
#######################################################################################################

#3.5.1.1 Ensure ufw is installed (Automated)
function 3.5.1.1 (){
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install ufw -y
  apt autoremove -y
}
#######################################################################################################

#3.5.1.3 Ensure ufw service is enabled (Automated)
function 3.5.1.3 (){
  ufw enable
  systemctl enable ufw
  ufw default allow outgoing
  ufw reload
}
#######################################################################################################

#3.5.1.7 Ensure ufw default deny firewall policy (Automated)
function 3.5.1.7 (){
  ufw default deny incoming
  #ufw default deny outgoing
  ufw default deny routed
  ufw allow git
  ufw allow in http
  ufw allow in https
  ufw allow out 53
  ufw logging on
  ufw allow out 22
  ufw allow in 22
  ufw default allow outgoing
}
#######################################################################################################

#3.5.3.1.1 Ensure iptables packages are installed (Automated)
function 3.5.3.1.1 (){
  echo -e "${RED}3.5.3.1.1${NC} Ensure iptables packages are installed"
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install -y iptables iptables-persistent
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure iptables packages are installed"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure iptables packages are installed"
  fi
}
#######################################################################################################

#3.5.3.3 Configure IPv6 ip6tables
function 3.5.3.3 (){
  while true; do
      read -p "Are you sure default deny firewall policy (for IPv4)? (y/n)" FIREWALL_POLICY
      if [[ ${FIREWALL_POLICY,,} =~ ^y$ ]]; then 
          break;
      else 
          echo -e "${RED}enter invalid answer${NC}"
      fi 
  done 

  if [[ $FIREWALL_POLICY == "y" ]]; then
  #     # open port 22 for ssh
  #     # block all traffic
    iptables -P INPUT DROP
    #iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6

    echo -e "${GREEN}Remediated:${NC} firewall policy is configured"
  else
      echo -e "${RED}Remediated:${NC} firewall policy is not configured"
  fi
}
#######################################################################################################

#3.5.4.2.1 Ensure IPv6 default deny firewall policy (Scored)
function 3.5.4.2.1 (){
  while true; do
      read -p "Are you sure default deny firewall policy (for IPv6)? (y/n)" FIREWALL_POLICY
      if [[ ${FIREWALL_POLICY,,} =~ ^y$ ]]; then 
          break;
      else 
          echo -e "${RED}enter invalid answer${NC}"
      fi 
  done 

  if [[ $FIREWALL_POLICY == "y" ]]; then
  # block all traffic
  ip6tables -P INPUT DROP
  ip6tables -P OUTPUT DROP
  ip6tables -P FORWARD DROPP
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6

    echo -e "${GREEN}Remediated:${NC} Ensure IPv6 default deny firewall policy"
  else
    echo -e "${RED}Remediated:${NC} Ensure IPv6 default deny firewall policy"
  fi
}
#######################################################################################################

#1.3.1 Ensure AIDE is installed (Automated)
function 1.3.1 (){
  echo -e "${RED}1.3.1 ${NC} Ensure AIDE is installed"
  apt update
  rm -rf /var/lib/dpkg/lock-frontend
  rm -rf /var/lib/dpkg/lock
  apt install aide aide-common -y
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  systemctl reload postfix
  echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure AIDE is installed"
  fi
}

#######################################################################################################

#1.3.2 Ensure filesystem integrity is regularly checked
function 1.3.2 (){
  cp ./config/aidecheck.service /etc/systemd/system/aidecheck.service
  cp ./config/aidecheck.timer /etc/systemd/system/aidecheck.timer
  chmod 0644 /etc/systemd/system/aidecheck.*
  systemctl reenable aidecheck.timer
  systemctl restart aidecheck.timer
  systemctl daemon-reload

  echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab
  echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /var/spool/cron/crontabs/root

  echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"
}
#######################################################################################################

#4.2.3 Ensure permissions on all logfiles are configured (Automated)
function 4.2.3 (){
  echo -e "${RED}4.2.3${NC} Ensure permissions on all logfiles are configured"
  chmod -R g-wx,o-rwx /var/log/*
  policystatus=$?
  if [[ "$policystatus" -eq 0 ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on all logfiles are configured"
  fi
}
#######################################################################################################

#4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Automated)
function 4.2.1.5 (){
  if grep -qsE '^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#"]+\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || grep -qsE '^[^#]\s*\S+\.\*\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then 
      echo -e "${GREEN}Remediated:${NC} Ensure rsyslog is configured to send logs to a remote log host"
  else 
      read -p "Enter Address of remote log host ? (Domain or IP) " REMOTE_LOG_ADDRESS
      if domain_checker $REMOTE_LOG_ADDRESS || ip_checker $REMOTE_LOG_ADDRESS; then 
          echo "*.* @@$REMOTE_LOG_ADDRESS" >> /etc/rsyslog.conf
          systemctl restart rsyslog
          echo -e "${GREEN}Remediated:${NC} Ensure rsyslog is configured to send logs to a remote log host"
      else
          echo -e "${RED}Your Input is not Valid${NC}"
          echo -e "${RED}UnableToRemediate:${NC} Ensure rsyslog is configured to send logs to a remote log host"
      fi
  fi
}

#######################################################################################################

#3.5.2.2 Ensure default deny firewall policy
function 3.5.2.2 (){
  local OUTPUT="1"
  echo -e "${RED}3.5.2.2 ${NC} Ensure default deny firewall policy"
  if ufw status verbose | grep allow 2> /dev/null 1>&2; then 
    ufw default deny incoming
    #ufw default deny outgoing
    ufw default deny routed
    local OUTPUT="0"
  else 
    local OUTPUT="0"
  fi 

  if [[ $OUTPUT == "0" ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure default deny firewall policy"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure default deny firewall policy"
  fi
}

#######################################################################################################

#3.5.4.1.1 Ensure default deny firewall policy
function 3.5.4.1.1 (){
  echo -e "${RED}3.5.4.1.1 ${NC} Ensure default deny firewall policy"
  if iptables -S | grep -i "\-P input\|\-P output\|-P FORWARD" | grep -i accept 2> /dev/null 1>&2; then 
    iptables -P INPUT DROP 
    iptables -P FORWARD DROP 
    iptables -P OUTPUT DROP 
    local OUTPUT="0"
  else 
    local OUTPUT="0"
  fi 

  if [[ $OUTPUT == "0" ]]; then
    echo -e "${GREEN}Remediated:${NC} Ensure default deny firewall policy"
  else
    echo -e "${RED}UnableToRemediate:${NC} Ensure default deny firewall policy"
  fi
}

#######################################################################################################

function firewall_selector (){
  while true; do 
    read -p "enter firewall name (iptable or ufw): " FIREWALL_NAME
    if [[ ${FIREWALL_NAME,,} =~ ^iptable$ ]]; then 
      3.5.3.1.1
      iptables_rules
      3.5.3.3
      3.5.4.2.1
      3.5.4.1.1
      break;
    elif [[ ${FIREWALL_NAME,,} =~ ^ufw$ ]]; then 
      3.5.2.3
      3.5.1.1
      3.5.1.3
      ufw_rules
      3.5.1.7
      3.5.2.2
      break;
    else 
      echo -e "${RED}Your must choose one of them (iptables or ufw)${NC}"
    fi
  done 
}

function iptables_rules () {
  # get list of listen ports
  netstat -nultp | grep LISTEN | grep -v ::: | awk '{print $4}' > /tmp/listen_ports_list
  for SOCKET in $(cat /tmp/listen_ports_list); do 
    local PORT=`echo $SOCKET | awk -F: '{print $2}'`
    iptables -A INPUT -p tcp --dport $PORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  done

  echo -e "${GREEN}Remediated:${NC} Ensure add rules for listen ports"
}

function ufw_rules () {
  # get list of listen ports
  netstat -nultp | grep LISTEN | grep -v ::: | awk '{print $4}' > /tmp/listen_ports_list
  for SOCKET in $(cat /tmp/listen_ports_list); do 
    local PORT=`echo $SOCKET | awk -F: '{print $2}'`
    ufw allow in $PORT
  done

  echo -e "${GREEN}Remediated:${NC} Ensure add rules for listen ports"
}
#######################################################################################################

#cat /tmp/list_of_packages_update
function 1.9_3 () {

  cat /tmp/list_of_packages_update

}

#######################################################################################################


change_nameserver
1.1.1.1
1.1.1.2
1.1.1.3
1.1.1.4
1.1.1.5
1.1.1.6_udf
1.1.1.6_squashfs
1.1.3_4_5
1.1.1.8_9
1.1.6
1.1.13
1.1.22_sticky
1.1.22
1.1.24
1.3.2_sudo
1.3.3
1.4.1
1.4.2
1.4.3
1.4.4
1.5.2
1.5.3
1.5.4
1.6.1.1
1.6.1.3
1.6.1.4
1.7.1
1.7.2
1.7.3
1.7.4
1.7.5
1.7.6
1.8.1
2.2.1.2
2.1.1.1
2.1.1.3
2.1.1.4
2.1.2
2.1.3
2.1.4
2.1.5
2.1.6
2.1.7
2.1.8
2.1.9
2.1.10
2.1.11
2.1.12
2.1.13
2.1.14
2.1.16
2.1.17
2.2.1
2.2.2
2.2.3
2.2.4
2.2.5
2.2.6
3.1.1
3.2.1
3.2.2
3.3.1
3.3.2
old_cis_1
3.3.3
3.3.4
3.3.5
3.3.6
3.3.7
3.3.8
3.3.9
3.4.1
3.4.1_tcp
3.4.2
3.4.3
3.4.4
4.1.1.1
4.1.1.2
4.1.1.3
4.1.1.4_audit
4.1.2.1
4.1.2.2
4.1.2.3
4.1.3
4.1.4
4.1.5
4.1.6
4.1.7
4.1.8
4.1.9
4.1.10
4.1.11
4.1.12
4.1.13
4.1.14
#4.1.15
4.1.15_sudo
4.1.16
4.1.17
4.2.1.1
4.2.1.2
4.2.1.3
4.2.1.4
4.2.1.6
4.2.2.1
4.2.2.2
4.2.2.3
4.4
5.1.1
5.1.2
5.1.3
5.1.4
5.1.5
5.1.6
5.1.7
5.2.1
5.3.1
ssh_protocol
5.3.2
5.3.3
5.3.4
5.2.21
5.2.22
5.2.23
5.3.5
5.3.6
5.3.7
5.3.8
5.3.9
5.3.10
5.3.12
5.3.14
5.3.15
5.3.16
5.3.17
5.3.18
5.4.1
5.4.1.2
5.3.2_lockout
5.4.3
5.4.4
5.5.1.1
5.5.1.2
5.5.1.3
5.5.1.4
#5.5.1.5 - dose not exist
5.5.2
5.5.3
5.5.4
5.5.5
5.6
6.1.2
6.1.3
6.1.4
6.1.5
6.1.6
6.1.7
6.1.8
6.1.9
6.1.11
6.1.12
6.2.1
6.2.8
6.2.12
5.1.8
3.3.2_etc
3.3.3_etc
1.3.1
1.3.2
4.2.3
1.9
firewall_selector
1.9_2
4.2.1.5
1.9_3

echo "Finish, Please reboot"
