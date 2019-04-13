#!/bin/bash


# Define colors...
RED=`tput bold && tput setaf 1`
GREEN=`tput bold && tput setaf 2`
YELLOW=`tput bold && tput setaf 3`
BLUE=`tput bold && tput setaf 4`
NC=`tput sgr0`

function RED(){
    echo -e "\n${RED}${1}${NC}"
}
function GREEN(){
    echo -e "\n${GREEN}${1}${NC}"
}
function YELLOW(){
    echo -e "\n${YELLOW}${1}${NC}"
}
function BLUE(){
    echo -e "\n${BLUE}${1}${NC}"
}

BLUE "Checking for NOPASSWD sudo commands... remove these lines if found!"
sudo grep -i NOPASSWD /etc/sudoers /etc/sudoers.d/*
BLUE "Checking for !authenticate sudo commands... remove these lines if found!"
sudo grep -i authenticate /etc/sudoers /etc/sudoers.d/*

BLUE "Checking for user accounts without home directories... remove those if found!"
sudo pwck -r

BLUE "Checking for duplicate UID 0 accounts... remove those if found!"
sudo awk -F: '$3 == 0 {print $1}' /etc/passwd

BLUE "Checking for files that have no owner... remove those if found!"
sudo find / -fstype ext4 -nouser 2>/dev/null

BLUE "Checking for files that have no group... remove those if found!"
sudo find / -fstype ext4 -nogroup 2>/dev/null

BLUE "Checking permissions for user home directories... correct these if needed!"
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

BLUE "Checking for world-writable files... remove these if found!"
find / -perm -002 -type f -exec ls -ld {} \; 

BLUE "Checking for world-writable directories... remove these if found!"
find / -xdev -perm -002 -type d -fstype xfs -exec ls -lLd {} \;

BLUE "Checking the permissions of 'cron.allow'... this should be root!"
ls -al /etc/cron.allow

BLUE "Checking for .shosts files on the system... remove these if found!"
find / -name '*.shosts'

BLUE "Checking for a shots.equiv file on the system... remove this if found!"
find / -name shosts.equiv