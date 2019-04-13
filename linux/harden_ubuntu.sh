#!/bin/bash
# Author: John Hammond
# Date: 28MAR2016
# Description:
#    harden_services.sh aims to offer all the functionality given in the "harden library"
#    which is a ton of functions stored in "functions_harden.sh". This script alone should
#    call the things necessary for a service. 
#    
#     Instructions
#
#        1. Setup your physical machine and run through the default installation of at least Ubuntu Server 14.04.
#        2. Run this script with it configured to do what you like.
#        3. Enjoy your secure (hopefully) server! 
#


RED=`tput setaf 1`                          # code for red console text
GREEN=`tput setaf 2`                        # code for green text
YELLOW=`tput setaf 3`                       # code for yellow text
NC=`tput sgr0`                              # Reset the text color


function update(){

    # This function is COMPLETE AND TESTED in regards to
    # hardenubuntu.com/hardenubuntu.com/initial-setup/system-updates.html

    echo "$FUNCNAME: ${GREEN}Updating your machine...${NC}"
    apt-get update
    echo "y" |  apt-get upgrade
    apt-get autoremove
    apt-get autoclean
}

function enable_security_updates(){

    # This function is COMPLETE AND TESTED in regards to
    # hardenubuntu.com/hardenubuntu.com/initial-setup/system-updates.html

    echo "$FUNCNAME: ${GREEN}Enabling security updates...${NC}"
    apt-get install unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
}

function disable_root_account(){

    # This function is COMPLETED AND TESTED in regards to
    # hardenubuntu.com/hardenubuntu.com/initial-setup/disable-root-account.html

    # This is typically already done by Ubuntu server, you cannot log in as
    # root, but any sudo commands work fine.
    # A better conversation to be had is how to make the changes so only
    # domain administrators can run commands with sudo, and only specific
    # commands.

    echo "$FUNCNAME: ${GREEN}Disabling the root account...${NC}"
    passwd -l root || panic
}

function disable_ipv6(){

    # This function is complete in regards to
    # hardenubuntu.com/hardenubuntu.com/server-setup/disable-ipv6.html

    # I don't see any real reason why we would ever need or even WANT this,
    # considering we WOULD LIKE to use IPv6, but I figured I would add the
    # function in so we at least have it.

    echo "$FUNCNAME: ${GREEN}Disabling IPv6...${NC}"

    sysctl_config_file="/etc/sysctl.conf"

    # echo "net.ipv6.conf.all.disable_ipv6 = 1" >> $sysctl_config_file
    # echo "net.ipv6.conf.default.disable_ipv6 = 1" >> $sysctl_config_file
    # echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> $sysctl_config_file

    echo "$FUNCNAME: ${GREEN}This is done in a section of the new $sysctl_config_file!${NC}"

    echo "$FUNCNAME: ${GREEN}Reloading sysctl so the changes take place...${NC}"

    sysctl -p

}

function disable_irqbalance(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/hardenubuntu.com/server-setup/disable-irqbalance/index.html

    echo "$FUNCNAME: ${GREEN}Disabling IRQBalance...${NC}"
    if [ -e /etc/default/irqbalance ]; then
        sed -i s/ENABLED=\"1\"1/ENABLED=\"0\"/g /etc/default/irqbalance
    fi
}

function remove_irqbalance(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/hardenubuntu.com/server-setup/disable-irqbalance/index.html

    echo "$FUNCNAME: ${GREEN}Removing IRQBalance...${NC}"
    
    echo "y" | apt-get purge irqbalance
}

function remove_bluetooth(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/hardenubuntu.com/server-setup/disable-irqbalance/index.html

    echo "$FUNCNAME: ${GREEN}Removing Bluetooth...${NC}"
    
    echo "y" | apt-get purge bluez
}

function enable_only_tty1(){

    # This function is COMPLETE AND TESTED in regards to
    # hardenubuntu.com/hardenubuntu.com/server-setup/secure-console.html

    echo "$FUNCNAME: ${GREEN}Enabling only tty1 (disabling everything else)...${NC}"

    # sed -i '/^\(tty1\|console\|:0\)$/! s/\(.*\)/\# \1/g' /etc/securetty

    cat <<EOF > /etc/securetty
console
tty1
EOF

    sed -i 's/ACTIVE_CONSOLES="\/dev\/tty\[1-6\]/ACTIVE_CONSOLES=\"\/dev\/tty1\"/g' /etc/default/console-setup

    mv /etc/init/tty2.conf /etc/init/tty2.conf_backup
    mv /etc/init/tty3.conf /etc/init/tty3.conf_backup
    mv /etc/init/tty4.conf /etc/init/tty4.conf_backup
    mv /etc/init/tty5.conf /etc/init/tty5.conf_backup
    mv /etc/init/tty6.conf /etc/init/tty6.conf_backup

    echo "$FUNCNAME: ${GREEN}You will need to reboot to see these changes!${NC}"
}

function remove_usb_storage_driver(){

    echo "$FUNCNAME: ${GREEN}Removing USB storage driver...${NC}"

    rm -f /lib/modules/3.19.0-25-generic/kernel/drivers/usb/storage/usb-storage.ko
}

function secure_shared_memory(){

    # This function is COMPLETE AND TESTED in regards to
    # hardenubuntu.com/hardenubuntu.com/server-setup/secure-shared-memory.html

    echo "$FUNCNAME: ${GREEN}Securing shared memory...${NC}"

    fstab_config_file="/etc/fstab"

    echo "# secure shared memory" >> $fstab_config_file
    echo "tmpfs     /run/shm    tmpfs   defaults,noexec,nosuid  0   0" >> $fstab_config_file

    echo "$FUNCNAME: ${GREEN}You will need to reboot for these changes to take effect.${NC}"
}

function secure_tcp_wrapper(){

    # This function is INCOMPLETE
    # hardenubuntu.com/hardenubuntu.com/server-setup/secure-tcp-wrapper.html

    echo "$FUNCNAME: ${GREEN}Securing TCP wrapper and limiting SSH connections...${NC}"

    # This is a curious conversation to have; should we allow any SSH connections?
    # Should we allow SSH connections from just one host, and have one machine
    # dedicated to be a "portal" to other machines? 

    echo "$FUNCNAME: ${RED}This secure_tcp_wrapper currently does nothing!${NC}"
}

function disable_uncommon_filetypes_in_modprobe(){

    echo "$FUNCNAME: ${GREEN} Disabling uncommon filetypes in modprobe...${NC}"

    cat <<EOF > /etc/modprobe.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install ipv6 /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    
}

function secure_temp_directories(){

    # This function is COMPLETE AND TESTED in regards
    # hardenubuntu.com/hardenubuntu.com/server-setup/secure-tmp-var-tmp.html

    echo "$FUNCNAME: ${GREEN}Securing temporary directories, so nothing can be executed within them...${NC}"    

    echo "$FUNCNAME: ${GREEN}Creating a specifc 1GB partition for /tmp...${NC}"

    dd if=/dev/zero of=/usr/tmpDSK bs=1024 count=1024000

    echo "$FUNCNAME: ${GREEN}Backing up current /tmp folder...${NC}"
    mkdir /tmpbackup
    cp -Rpf /tmp /tmpbackup

    echo "$FUNCNAME: ${GREEN}Mounting the new /tmp partition and setting hard permissions...${NC}"
    mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDSK /tmp
    chmod 1777 /tmp

    echo "$FUNCNAME: ${GREEN}Copying and removing the backup temp folder...${NC}"
    cp -Rpf /tmpbackup/* /tmp/
    rm -rf /tmpbackup/*

    echo "$FUNCNAME: ${GREEN}Setting the new /tmp folder in fstab...${NC}"
    # This is where my progress ends for this function... 
    echo "/usr/tmpDSK /tmp tmpfs loop,nosuid,noexec,rw 0 0" >> /etc/fstab

    mount -o remount /tmp

    # Here we can test running a binary or script in the temp directory

    echo "$FUNCNAME: ${GREEN}Creating a symbolic link for /var/tmp...${NC}"
    mkdir /var/tmpold
    mv /var/tmp /var/tmpold
    ln -s /tmp /var/tmp
    cp -prf /var/tmpold/* /tmp/

    echo "$FUNCNAME: ${GREEN}You should restart your machine for the changes to take effect.${NC}"
}

function reboot_when_out_of_memory(){

    # This function is complete in regards to 
    # hardenubuntu.com/hardenubuntu.com/server-setup/server-stability.html
    
    echo "$FUNCNAME: ${GREEN}Enabling reboot after an Out of Memory error...${NC}"

    sysctl_config_file="/etc/syctl.conf"

    echo "$FUNCNAME: ${GREEN}This is done in a section of the new $sysctl_config_file!${NC}"
#   echo "vm.panic_on_oom=1" >> $sysctl_config_file
#   echo "kernel.panic=10" >> $sysctl_config_file

}

function limit_number_of_processes(){

    # hardenubuntu.com/hardenubuntu.com/server-setup/set-security-limits.html

    # This function is seemingly unnecessary after testing....
    # Upon testing with a common fork bomb, `:(){ :|: &};:`,
    # it seems our Ubuntu Server system is already set up to limit processes
    # and it will not crash the system. It will, however, make the shell
    # practically unusable by printing out a bunch of fork errors..

    echo "$FUNCNAME: ${GREEN}Limiting number of processes to 100 for all users (except root)...${NC}"

    security_limits_file='/etc/security/limits.conf'

    echo "* hard nproc 100" >> $security_limits_file

}

function disable_compilers(){

    # hardenubuntu.com/hardenubuntu.com/software/disable-compilers/index.html

    # This function is seemingly unnecessary after testing; the Ubuntu Server
    # does not come with any compilers pre-installed!

    echo "$FUNCNAME: ${GREEN}Disabling the use of common compilers...${NC}"

    compilers=(
            "/usr/bin/byacc"
            "/usr/bin/yacc"
            "/usr/bin/bcc"
            "/usr/bin/kgcc"
            "/usr/bin/cc"
            "/usr/bin/gcc"
            "/usr/bin/c++"
            "/usr/bin/g++"
        )

    for compiler in ${compilers[@]}; do
        if command_exists ${compiler}; then
            echo "$FUNCNAME: ${GREEN}Changing permissions to 000 for ${compiler}...${NC}"
            chmod 000 ${compiler}
        fi
    done
}

function disable_anacron(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-anacron/

    echo "$FUNCNAME: ${GREEN}Disabling the anacron service...${NC}"

    sed -i 's/^\(25\|47\|52\)\(.*\)/\# \1\2/g' /etc/crontab
}


function disable_apport(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-apport/

    echo "$FUNCNAME: ${GREEN}Disabling the apport service...${NC}"

    sed -i 's/enabled\=1/enabled\=0/g' /etc/default/apport
}


function remove_apport(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-apport/

    echo "$FUNCNAME: ${GREEN}Removing the apport service...${NC}"

    echo "y" | apt-get purge apport
}



function disable_atd(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-atd/

    echo "$FUNCNAME: ${GREEN}Disabling the atd service...${NC}"

    echo 'manual' > /etc/init/atd.override
}


function remove_atd(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-atd/

    echo "$FUNCNAME: ${GREEN}Removing the atd service...${NC}"
    if command_exists at; then
        echo "y" | apt-get purge at
    fi
        
}


function disable_autofs(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-autofs/

    echo "$FUNCNAME: ${GREEN}Disabling autofs functionality...${NC}"

    echo 'SUBSYSTEM=="usb", ENV{UDISKS_AUTO}="0"' > /etc/udev/rules.d/85-no-automount.rules
    # service udev restart # this tends to make it break, and we can reboot anyway, so...
}

function disable_avahi(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-avahi/

    echo "$FUNCNAME: ${GREEN}Disabling the avahi service...${NC}"

    echo 'manual' > /etc/init/avahi-daemon.override
}

function remove_avahi(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-avahi/

    echo "$FUNCNAME: ${GREEN}Removing the avahi service...${NC}"

    echo 'y' | apt-get remove avahi-daemon avahi-utils
}

function disable_bluetooth(){

    # hardenubuntu.com/disable-services/disable-bluetooth/

    # Our Ubuntu Server does not come with bluetooth!

    # echo "$FUNCNAME: ${GREEN}Disabling the bluetooth service...${NC}"

    echo "$FUNCNAME: ${YELLOW}This disable_bluetooth function does not have to do anything!${NC}"
}

function disable_cups(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-cups/

    echo "$FUNCNAME: ${GREEN}Disabling the cups service...${NC}"

    echo 'manual' > /etc/init/cups.override
}

function remove_cups(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-cups/

    echo "$FUNCNAME: ${GREEN}Removing the cups service...${NC}"

    echo "y" | apt-get remove cups
}


function remove_dovecot(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-dovecot/

    echo "$FUNCNAME: ${GREEN}Removing the dovecot service...${NC}"

    echo "y" | apt-get purge dovecot-*
}

function disable_modemmanager(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-modemmanager/

    echo "$FUNCNAME: ${GREEN}Disabling the modemmanager service...${NC}"

    echo 'manual' > /etc/init/modemmanager.override
}

function remove_modemmanager(){

    # This function is COMPLETE AND TESTED in regards to 
    # hardenubuntu.com/disable-services/disable-modemmanager/

    echo "$FUNCNAME: ${GREEN}Removing the modemmanager service...${NC}"

    echo "y" | apt-get purge modemmanager
}

function remove_nfs(){

    # This function is COMPLETE AND TESTED in regards to 
    # http://hardenubuntu.com/disable-services/disable-nfs/

    echo "$FUNCNAME: ${GREEN}Removing the NFS functionality...${NC}"

    echo "y" | apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs
}


function remove_snmp(){

    # This function is COMPLETE AND TESTED in regards to 
    # http://hardenubuntu.com/disable-services/disable-nfs/

    # I do not know if this is actually installed an in use in our Ubuntu?

    echo "$FUNCNAME: ${GREEN}Removing the SNMP functionality service...${NC}"

    echo "y" | apt-get purge --auto-remove snmp
}


function remove_telnet(){

    # This function is COMPLETE AND TESTED in regards to 
    # http://hardenubuntu.com/disable-services/disable-telnet/

    echo "$FUNCNAME: ${GREEN}Removing Telnet (thank god)...${NC}"
    if command_exists telnet; then
        echo "y" | apt-get purge telnetd inetutils-telnetd telnetd-ssl
    fi
}

function remove_whoopsie(){

    # This function is COMPLETE AND TESTED in regards to 
    # http://hardenubuntu.com/disable-services/disable-telnet/

    echo "$FUNCNAME: ${GREEN}Removing the Whoopsie service...${NC}"
    echo "y" | apt-get purge whoopsie
}

function remove_zeitgeist(){

    # This function is COMPLETE AND TESTED in regards to 
    # http://hardenubuntu.com/disable-services/disable-telnet/

    # I don't know if this actually installed either.

    echo "$FUNCNAME: ${GREEN}Removing the Zeitgeist service...${NC}"

    echo "y" | apt-get purge zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist
}

function disable_gnome_automounting(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Disabling GNOME automounting...${NC}"
    echo "$FUNCNAME: ${GREEN}This should only run if it is working on a desktop client.${NC}"

    if command_exists gconftool-2 ; then
        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /desktop/gnome/volume_manager/automount_media false
        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /desktop/gnome/volume_manager/automount_drives false
    else
        echo "$FUNCNAME: ${YELLOW}gconftool-2 not found -- must not be running on a desktop. Doing nothing!.${NC}"
    fi
}

function disable_gnome_thumbnailers(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Disabling GNOME thumbnailers...${NC}"
    echo "$FUNCNAME: ${GREEN}This should only run if it is working on a desktop client.${NC}"

    if command_exists gconftool-2 ; then
        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /desktop/gnome/thumbnailers/disable_all true
    else
        echo "$FUNCNAME: ${YELLOW}gconftool-2 not found -- must not be running on a desktop. Doing nothing!.${NC}"
    fi
}

function verify_permissions_on_crucial_files(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting permissions on specific files...${NC}"

    echo "$FUNCNAME: ${GREEN}Making sure root own /etc/shadow & passwd & group & gshadow...${NC}"
    chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow
    
    echo "$FUNCNAME: ${GREEN}Setting permissions to 644 on /etc/passwd and /etc/group...${NC}"
    chmod 644 /etc/passwd /etc/group

    echo "$FUNCNAME: ${GREEN}Setting permissions to 400 on /etc/shadow and /etc/gshadow...${NC}"
    chmod 500 /etc/shadow /etc/gshadow
}

function verify_world_writeable_dirs_have_sticky(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting that all world writable directories have their sticky bit set...${NC}"

    find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print | while read directory; do
        echo "$FUNCNAME: ${GREEN} Making sticky on ${directory}..."
        chmod +t ${directory}
    done
}

function verify_no_world_writable_files(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting that there are no world-writable files on the system...${NC}"

    find / -xdev -type f -perm -0002 -print | while read file; do
        echo "$FUNCNAME: ${GREEN} Removing world-write privilege on ${file}..."
        chmod o-w ${file}
    done
}

function verify_no_setuid_files(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting that there are no unauthorized SETUID/SETGID files on the system...${NC}"

    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print| while read file; do

        if grep -Fxq "$file" "allowed_suid_list.txt"
        then 
            # This program is allowed; leave it alone.
            echo "$FUNCNAME: ${GREEN} ${file} is in the ALLOWED_SUID_LIST! Doing nothing... ${NC}" > /dev/null
        else
            echo "$FUNCNAME: ${GREEN} Removing SUID/SGID bit on ${file}...${NC}"
            chmod -s ${file}
        fi
    done
}

function verify_no_unowned_files(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting that there are no unowned files on the system...${NC}"

    find / -xdev \( -nouser -o -nogroup \) -print| while read file; do
        echo "$FUNCNAME: ${GREEN} Removing unowned file ${file}..."
        rm -f ${file}
    done
}

function verify_any_world_writable_directories_are_owned_by_root(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Verifying/setting that any world writable directories are owned by root...${NC}"

    find / -xdev -type d -perm -0002 -uid +500 -print| while read file; do
        echo "$FUNCNAME: ${GREEN} Changing this world writeable directory to be owned only by root: ${file}..."
        chown root:root ${file}
    done
}

function set_umask_to_027(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Setting global umask to 027 in /etc/login.defs...${NC}"

    sed -i "s/UMASK.\*/UMASK\ \ \ \ \ \ \ \ \ \ \ 027/g" /etc/login.defs

    sed -i 's/umask 002/umask 027/g' /etc/profile
}


function disable_core_dumps(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Disabling memory core dumps for all users in /etc/security/limits.conf...${NC}"

    sysctl_config_file="/etc/sysctl.conf"
    
    echo -e "*\t\thard\t core\t\t0" >> /etc/security/limits.conf
    
    echo "$FUNCNAME: ${GREEN}This is done in a section of the new $sysctl_config_file!${NC}"
    # echo "fs.suid_dumpable = 0" >> $sysctl_config_file

}

function enable_execshield(){

    # This function is COMPLETE AND TESTED 

    echo "$FUNCNAME: ${GREEN}Enabling ExecShield to protect against buffer overflows in /etc/security/limits.conf....${NC}"

    sysctl_config_file="/etc/sysctl.conf"
    echo "$FUNCNAME: ${GREEN}This is done in a section of the new $sysctl_config_file!${NC}"
    
    # echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    # echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf

}

function disable_prelink(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Disabling prelink...${NC}"
    if command_exists /usr/sbin/prelink; then
        echo "PRELINKING=no" >> /etc/sysconfig/prelink
        echo "$FUNCNAME: ${GREEN}Reverting binaries and libraries back to original content before prelinking...${NC}"
        /usr/sbin/prelink -ua
    else
        echo "$FUNCNAME: ${YELLOW}Prelink was not found on this system! Doing nothing...${NC}"
    fi
}


function disable_nonhuman_system_accounts(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Disabling 'non-human' system accounts...${NC}"

    awk -F: '{print $1 ":" $3 ":" $7}' /etc/passwd | while read line; do
        username=`echo $line | cut -d":" -f1`
        numid=`echo $line | cut -d":" -f2`

        if [ $numid -lt 500 ] && [ "$numid" != "0" ]; then

            echo "$FUNCNAME: ${GREEN}Locking the password for the account ${username}...${NC}"
            usermod -L $username
            echo "$FUNCNAME: ${GREEN}Disabling the shell for the account ${username}...${NC}"
            usermod -s /usr/sbin/nologin $username
        fi
    done
}

function verify_no_accounts_have_empty_passwords(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting no accounts have empty passwords in /etc/shadow...${NC}"
    awk -F: '($2 == "") {print}' /etc/shadow | cut -d":" -f1 | while read line; do
        echo "$FUNCNAME: ${GREEN} This account '$line' has an empty password! Locking account...${NC}"
        usermod -L $line
    done
}

function verify_all_password_hashes_are_shadowed(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting no accounts have visible hashed passwords in /etc/passwd...${NC}"
    awk -F: '($2 != "x") {print}' /etc/passwd | cut -d":" -f1 | while read line; do
        echo "$FUNCNAME: ${GREEN} This account '$line' has an hashed password visible in /etc/passwd! Locking account...${NC}"
        usermod -L $line
    done
}

function verify_no_other_accounts_have_zero_uids(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting no accounts have a UID of 0 (only root should!)...${NC}"
    awk -F: '($3 == "0") {print}' /etc/passwd | cut -d":" -f1 | while read line; do
        if [ "${line}" != "root" ]; then
            echo "$FUNCNAME: ${GREEN} This account '$line' has a UID of 0, and it shouldn't! Locking account...${NC}"
            usermod -L $line
        fi
    done
}

function force_default_path_environment_variable(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Forcing PATH to be the default value...${NC}"
    export PATH="/usr/local/sbin:/usr/local/bin/:/usr/sbin/:/sbin/:/usr/bin/:/bin/:/usr/games/:/usr/local/games/"
}

function verify_path_directory_permissions(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting that all PATH directories are chmod 755 and owned by only root...${NC}"
    echo $PATH | tr ":" "\n" | while read line; do
        chmod 755 $line
        chown root:root $line
    done
}


function verify_home_directory_permissions(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting that all HOME directories are chmod 755 and owned by only the home user...${NC}"
    ls /home | while read line; do
        chmod g-w /home/$line
        chmod o-rwx /home/$line
        chown $line:$line /home/$line
    done
}

function verify_home_directory_dot_files(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting that all HOME directory dot files are not world-writable...${NC}"
    ls /home | while read line; do
        ls -ld /home/$line/.[A-Za-z0-9]* | while read file; do
            chmod go-w /home/$line/$file
        done
    done
}

function verify_no_home_netrc_file(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Verifying/setting that no HOME directory has a .netrc...${NC}"
    ls /home | while read line; do
        rm -f /home/$line/.netrc
    done
}

function create_shell_timeout(){

    # This function is COMPLETE AND TESTED

    echo "$FUNCNAME: ${GREEN}Creating a 300 second timeout for the shell...${NC}"
    cat <<EOF > /etc/profile.d/tmout.sh
TMOUT=300
readonly TMOUT
export TMOUT
EOF
}

function create_desktop_timeout(){

    timeout_in_minutes="3"

    echo "$FUNCNAME: ${GREEN}Creating a $timeout_in_minutes minute timeout for the desktop...${NC}"
    echo "$FUNCNAME: ${GREEN}This should only run if it is working on a desktop client.${NC}"


    if command_exists gconftool-2 ; then
        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/idle_activation_enabled true

        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/lock_enabled true

        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome-screensaver/mode blank-only

        gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type int --set /apps/gnome-screensaver/idle_delay $timeout_in_minutes
    else
        echo "$FUNCNAME: ${YELLOW}gconftool-2 not found -- must not be running on a desktop. Doing nothing!.${NC}"
    fi
}

function change_system_banner(){

    echo "$FUNCNAME: ${GREEN}Changing the system banner to some sarcastic one-liner...${NC}"
    
    new_banner="\nWant to hear a joke? Just look at the scoreboard! :D \n"
    echo -e $new_banner > /etc/issue
}

function install_selinux(){

    echo "$FUNCNAME: ${GREEN}Installing SELinux...${NC}"
    if ! command_exists sestatus; then
        ifdown eth0
        ifdown eth1
        ifup eth1
        
        apt-get -y install selinux-basics

        ifdown eth1
        ifdown eth0
        ifup eth0
    fi
}

function configure_selinux(){

    echo "$FUNCNAME: ${GREEN}Configuring SELinux...${NC}"
    
    sed -i s/SELINUX=.\*/SELINUX=enforcing/g /etc/selinux/config
    sed -i s/SELINUXTYPE=.\*/SELINUXTYPE=targeted/g /etc/selinux/config

    sed -i s/selinux=0//g /boot/grub/grub.cfg
    sed -i s/enforcing=0//g /boot/grub/grub.cfg
}

function change_motd(){

    echo "$FUNCNAME: ${GREEN}Changing the Message of the Day login splash...${NC}"
    rm -f /etc/update-motd.d/*
    echo "Hello and welcome." > /etc/update-motd.d/00-header
    chmod 700 /etc/update-motd.d/00-header
    chown root:root /etc/update-motd.d/00-header

}

function always_kill_unwanted_programs(){

    echo "$FUNCNAME: ${GREEN}Installing 'montorr' to always kill unwanted programs...${NC}"

    cp montorr /usr/bin/
    chmod 700 /usr/bin/montorr
    chown root:root /usr/bin/montorr
    cat <<EOF > /etc/init/montorr.conf
start on startup
task
exec /usr/bin/montorr &
EOF
    
    initctl reload-configuration

    # sed -i s+^exit\ 0+nohup\ /usr/bin/montorr\ \&\\n\ exit\ 0+g /etc/rc.local
}

function use_proper_sysctl(){

    echo "$FUNCNAME: ${GREEN}Replacing /etc/sysctl.conf with the hardened one...${NC}"
    cp -f sysctl.conf /etc/sysctl.conf
}


function set_better_resolution(){

    if command_exists xrandr; then
        echo "$FUNCNAME: ${GREEN}Changing to a sane resolution of 1366x768...${NC}"
        xrandr -s 1366x768
    fi
}



# Print a fatal error message and exit
# Usage:
#   some_command parameter || panic
#   
#   This will print the panic message and exit if `some_command` fails.
function panic(){
    echo "$FUNCNAME: ${RED}fatal error${NC}"
    exit -1
}

# Test if we actually have a command on the current box.
# Usage:
#    if command_exists <command> ; then
#           # do stuff if the command exists!
#    else
#           # do other stuff is the command does not exist
#    fi
function command_exists(){
    type "$1" &> /dev/null
}



function main(){

    echo "$FUNCNAME: ${GREEN}Running harden_service.sh...${NC}"

    # update || panic
    # enable_security_updates || panic 
    disable_root_account || panic
    # disable_irqbalance || panic
    # remove_irqbalance || panic
    # remove_bluetooth || panic
    # enable_only_tty1 || panic
    secure_temp_directories || panic

    remove_usb_storage_driver || panic
    disable_uncommon_filetypes_in_modprobe || panic

    disable_gnome_automounting || panic
    disable_gnome_thumbnailers || panic

    verify_permissions_on_crucial_files || panic
    verify_world_writeable_dirs_have_sticky || panic
    verify_no_world_writable_files || panic
    verify_no_setuid_files || panic
    verify_no_unowned_files || panic
    verify_any_world_writable_directories_are_owned_by_root || panic

    set_umask_to_027 || panic
    disable_core_dumps || panic
    enable_execshield || panic
    disable_prelink || panic
    disable_nonhuman_system_accounts || panic
    verify_no_accounts_have_empty_passwords || panic
    verify_all_password_hashes_are_shadowed || panic
    verify_no_other_accounts_have_zero_uids || panic
    create_shell_timeout || panic
    create_desktop_timeout || panic

    change_system_banner || panic
    # install_selinux || panic
    configure_selinux || panic

    use_proper_sysctl || panic

    change_motd || panic
    
    # always_kill_unwanted_programs || panic

    secure_shared_memory || panic
    reboot_when_out_of_memory || panic
    disable_compilers || panic
    limit_number_of_processes || panic
    disable_anacron || panic 
    disable_apport || panic 
    disable_atd || panic 
    disable_autofs || panic 
    disable_avahi || panic 
    disable_bluetooth || panic 
    disable_cups || panic

    # I do this so we don't accidentally kill our mail server...
    if [ ! remove_dovecot ]; then
        remove_dovecot || panic
    fi
    

    disable_modemmanager || panic
    remove_nfs || panic
    remove_snmp || panic
    remove_telnet || panic
    remove_whoopsie || panic
    remove_zeitgeist || panic

    force_default_path_environment_variable || panic
    verify_path_directory_permissions || panic
    verify_home_directory_permissions || panic
    
    echo "$FUNCNAME: ${GREEN}All done! You should DEFINITELY reboot your machine for these changes!${NC}"

    exit 0  
}

# Make sure the user is root (e.g. running as sudo)
if [ "$UID" != "0" ]; then
    echo "$0: ${RED}you must be root to configure this box.${NC}"
    exit -1
fi

# This makes it so every function has a "pre-declaration" of all the functions
main "$@"