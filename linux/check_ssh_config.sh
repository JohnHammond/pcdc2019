#!/bin/bash

# Define colors...
RED=`tput bold && tput setaf 1`
GREEN=`tput bold && tput setaf 2`
YELLOW=`tput bold && tput setaf 3`
BLUE=`tput bold && tput setaf 4`
NC=`tput sgr0`

function RED(){
    echo -e "${RED}${1}${NC}"
}
function GREEN(){
    echo -e "${GREEN}${1}${NC}"
}
function YELLOW(){
    echo -e "${YELLOW}${1}${NC}"
}
function BLUE(){
    echo -e "${BLUE}${1}${NC}"
}

SSH_CONFIG_FILE="/etc/ssh/sshd_config"


grep -E "^Port 22$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is running on a nonstandard port! Config reads as follows:"
    grep -i "Port" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running on Port 22!"
fi


grep -E "^Protocol 2$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not running on Protocol 2port! Config reads as follows:"
    grep -i "Protocol" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with Protocol 2!"
fi

grep -E "^UsePrivilegeSeparation yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not running with UsePrivilegeSeparation yes! Config reads as follows:"
    grep -i "privilege" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'UsePrivilegeSeparation yes'!"
fi


grep -E "^LoginGraceTime 120$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH Login grace time is not set to the default 2 minutes! Config reads as follows:"
    grep -i "LoginGraceTime" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'LoginGraceTime 120'!"
fi


grep -E "^PermitRootLogin no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH may allow root logins! Config reads as follows:"
    grep -i "root" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'PermitRootLogin no'!"
fi

grep -E "^StrictModes yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not running with Strict Modes! Config reads as follows:"
    grep -i "StrictModes" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'StrictModes yes'!"
fi


grep -E "^RSAAuthentication yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not using RSA for authentication! Config reads as follows:"
    grep -i "RSAAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'RSAAuthentication yes'!"
fi


grep -E "^PubkeyAuthentication yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not using public keys for authentication! Config reads as follows:"
    grep -i "PubkeyAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'PubkeyAuthentication yes'!"
fi


grep -E "^IgnoreRhosts yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH is not ignoring rhosts files! Config reads as follows:"
    grep -i "ignorerhosts" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'IgnoreRhosts yes'!"
fi


grep -E "^RhostsRSAAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be using rhosts authentication! Config reads as follows:"
    grep -i "rhostsrsa" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'RhostsRSAAuthentication no'!"
fi


grep -E "^RhostsRSAAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be using rhosts authentication! Config reads as follows:"
    grep -i "rhostsrsa" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'RhostsRSAAuthentication no'!"
fi


grep -E "^HostbasedAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might not be using HostbasedAuthentication! Config reads as follows:"
    grep -i "HostbasedAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'HostbasedAuthentication no'!"
fi


grep -E "^IgnoreUserKnownHosts yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be using known hosts files! Config reads as follows:"
    grep -i "userknownhosts" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'IgnoreUserKnownHosts yes'!"
fi


grep -E "^PermitEmptyPasswords no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be accepting empty passwords! Config reads as follows:"
    grep -i "emptypasswords" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'PermitEmptyPasswords no'!"
fi


grep -E "^ChallengeResponseAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be doing strange PAM challenges! Config reads as follows:"
    grep -i "ChallengeResponseAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'ChallengeResponseAuthentication no'!"
fi


grep -E "^#PasswordAuthentication yes$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be allowing cleartext passwords! Config reads as follows:"
    grep -i "PasswordAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with '#PasswordAuthentication yes'!"
fi

grep -E "^KerberosAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be allowing KerberosAuthentication! Config reads as follows:"
    grep -i "KerberosAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'KerberosAuthentication no'!"
fi

grep -E "^KerberosAuthentication no$" $SSH_CONFIG_FILE --color=none >/dev/null
if [ $? -ne 0 ]
then
    YELLOW "SSH might be allowing KerberosAuthentication! Config reads as follows:"
    grep -i "KerberosAuthentication" $SSH_CONFIG_FILE --color=none
else
    GREEN "SSH is running with 'KerberosAuthentication no'!"
fi
