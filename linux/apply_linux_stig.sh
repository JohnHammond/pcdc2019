#!/bin/bash

if  [ $UID -ne 0 ]
then
    echo "[ERROR] You must run this script as root!"
    exit
fi

sudo sed -i 's/# ucredit = 0/ucredit = -1/g' /etc/security/pwquality.conf
sudo sed -i 's/# lcredit = 0/lcredit = -1/g' /etc/security/pwquality.conf
sudo sed -i 's/# dcredit = 0/dcredit = -1/g' /etc/security/pwquality.conf
sudo sed -i 's/# ocredit = 0/ocredit = -1/g' /etc/security/pwquality.conf
sudo sed -i 's/# difok = 1/difok = 8/g' /etc/security/pwquality.conf
sudo sed -i 's/# minclass = 0/minclass = 4/g' /etc/security/pwquality.conf
sudo sed -i 's/# maxrepeat = 0/maxrepeat = 3/g' /etc/security/pwquality.conf
sudo sed -i 's/# maxclassrepeat = 0/maxrepeat = 4/g' /etc/security/pwquality.conf
sudo sed -i 's/# minlen = 8/minlen = 15/g' /etc/security/pwquality.conf

sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t1/g' /etc/login.defs
sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t60/g' /etc/login.defs


sudo sed -i 's/#PermitEmptyPasswords/PermitEmptyPasswords/g' /etc/ssh/sshd_config
sudo sed -i 's/# PermitEmptyPasswords/PermitEmptyPasswords/g' /etc/ssh/sshd_config
sudo sed -i 's/PermitEmptyPasswords/PermitEmptyPasswords no #/g' /etc/ssh/sshd_config

# V-72225
sudo sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
sudo sed -i 's/# Banner/Banner/g' /etc/ssh/sshd_config
sudo sed -i 's/Banner/Banner /etc/issue #/g' /etc/ssh/sshd_config

# V-72239
sudo sed -i 's/#RhostsRSAAuthentication/RhostsRSAAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/# RhostsRSAAuthentication/RhostsRSAAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/RhostsRSAAuthentication/RhostsRSAAuthentication no #/g' /etc/ssh/sshd_config

# V-72243
sudo sed -i 's/#IgnoreRhosts/IgnoreRhosts/g' /etc/ssh/sshd_config
sudo sed -i 's/# IgnoreRhosts/IgnoreRhosts/g' /etc/ssh/sshd_config
sudo sed -i 's/IgnoreRhosts/IgnoreRhosts yes #/g' /etc/ssh/sshd_config

# For SSH, you can also set a ClientAlive timeout interval!!

# V-722245
sudo sed -i 's/#PrintLastLog/PrintLastLog/g' /etc/ssh/sshd_config
sudo sed -i 's/# PrintLastLog/PrintLastLog/g' /etc/ssh/sshd_config
sudo sed -i 's/PrintLastLog/PrintLastLog yes #/g' /etc/ssh/sshd_config

# V-722247
sudo sed -i 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
sudo sed -i 's/# PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
sudo sed -i 's/PermitRootLogin/PermitRootLogin no #/g' /etc/ssh/sshd_config


# V-722249
sudo sed -i 's/#IgnoreUserKnownHosts/IgnoreUserKnownHosts/g' /etc/ssh/sshd_config
sudo sed -i 's/# IgnoreUserKnownHosts/IgnoreUserKnownHosts/g' /etc/ssh/sshd_config
sudo sed -i 's/IgnoreUserKnownHosts/IgnoreUserKnownHosts yes #/g' /etc/ssh/sshd_config


# V-722259
sudo sed -i 's/#GSSAPIAuthentication/GSSAPIAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/# GSSAPIAuthentication/GSSAPIAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/GSSAPIAuthentication/GSSAPIAuthentication no #/g' /etc/ssh/sshd_config

# V-722261
sudo sed -i 's/#KerberosAuthentication/KerberosAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/# KerberosAuthentication/KerberosAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/KerberosAuthentication/KerberosAuthentication no #/g' /etc/ssh/sshd_config


# V-722263
sudo sed -i 's/#StrictModes/StrictModes/g' /etc/ssh/sshd_config
sudo sed -i 's/# StrictModes/StrictModes/g' /etc/ssh/sshd_config
sudo sed -i 's/StrictModes/StrictModes yes #/g' /etc/ssh/sshd_config


# V-722265
sudo sed -i 's/#UsePrivilegeSeparation/UsePrivilegeSeparation/g' /etc/ssh/sshd_config
sudo sed -i 's/# UsePrivilegeSeparation/UsePrivilegeSeparation/g' /etc/ssh/sshd_config
sudo sed -i 's/UsePrivilegeSeparation/UsePrivilegeSeparation yes #/g' /etc/ssh/sshd_config



# V-722267
sudo sed -i 's/#Compression/Compression/g' /etc/ssh/sshd_config
sudo sed -i 's/# Compression/Compression/g' /etc/ssh/sshd_config
sudo sed -i 's/Compression/Compression no #/g' /etc/ssh/sshd_config


# V-72275
sudo sed -i "s/.*lastlog.*/session required pam_lastlog.so showfailed/g" /etc/pam.d/login

# V-72303
sudo sed -i "s/.*X11Forwarding.*/X11Forwarding yes/g" /etc/ssh/sshd_config

# V-72309
sudo sed -i "s/.*net\.ipv4\.ip_forward.*/net.ipv4.ip_forward = 0 # SET BY STIG/g" /etc/sysctl.conf


# V-77825
sudo sed -i "s/.*kernel\.randomize_va_space.*/kernel.randomize_va_space=2 # SET BY STIG/g" /etc/sysctl.conf


# V-73159
echo "password required pam_pwquality.so retry=3" >> /etc/pam.d/passwd



sudo sed -i 's/#INACTIVE/INACTIVE/g' /etc/default/useradd
sudo sed -i 's/# INACTIVE/INACTIVE/g' /etc/default/useradd
sudo sed -i 's/INACTIVE/INACTIVE=0 #/g' /etc/default/useradd

sudo sed -i 's/#FAIL_DELAY/FAIL_DELAY/g' /etc/login.defs
sudo sed -i 's/# FAIL_DELAY/FAIL_DELAY/g' /etc/login.defs
sudo sed -i 's/FAIL_DELAY/FAIL_DELAY 4/g' /etc/login.defs


sudo sed -i 's/#UMASK/UMASK/g' /etc/login.defs
sudo sed -i 's/# UMASK/UMASK/g' /etc/login.defs
sudo sed -i 's/UMASK/UMASK 077 #/g' /etc/login.defs


sudo sed -i 's/#CREATE_HOME/CREATE_HOME/g' /etc/login.defs
sudo sed -i 's/# CREATE_HOME/CREATE_HOME/g' /etc/login.defs
sudo sed -i 's/CREATE_HOME/CREATE_HOME yes #/g' /etc/login.defs



# I have not seen this PermitUserEnvironment option set in the default SSH config...
# so add it in "by hand"!
#sudo sed -i 's/PermitUserEnvironment/PermitUserEnvironment no #/g' /etc/ssh/sshd_config
sudo echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

sudo sed -i 's/#HostbasedAuthentication/HostbasedAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/# HostbasedAuthentication/HostbasedAuthentication/g' /etc/ssh/sshd_config
sudo sed -i 's/HostbasedAuthentication/HostbasedAuthentication no #/g' /etc/ssh/sshd_config


sudo apt remove rsh-server ypserv

sudo systemctl disable autofs

sudo systemctl mask ctrl-alt-del.target


cat > /etc/issue <<EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF



# Restart the SSH server for all configuration file changes to be made...
sudo service ssh restart