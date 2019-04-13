Linux Toolkit
=======================

CentOS
----------

Installing `git`:

```
yum update -y nss curl libcurl git
```

Priority
------------------

1. Run `LinEnum.sh | tee -a enum_log.txt` 
2. Run `monitor.sh` on `lsof`, `netstat`, `sudo -l/etc/sudoers`, `ps aux`, `/etc/passwd`, `/etc/shadow`
3. Run harden scripts
4. 


Toolkit
--------

* `rkhunter`: [https://github.com/installation/rkhunter](https://github.com/installation/rkhunter)

* `maldet`: [https://github.com/rfxn/linux-malware-detect](https://github.com/rfxn/linux-malware-detect)

* `chkrootkit`: [https://github.com/Magentron/chkrootkit](https://github.com/Magentron/chkrootkit)

Files Information
-------------

* [`LinEnum.sh`](LinEnum.sh)

    Added by John Hammond. 


--------------

Other  
========


__View logged in users:__

```
# w
```

__Show if a user has ever logged in remotely:__

```
# lastlog

# last
```

__View failed logins:__

```
# faillog -a
```

__View local user accounts:__

```
# cat /etc/passwd

# cat /etc/shadow
```

__View local groups:__

```
# cat /etc/group
```

__View sudo access:__

```
# cat /etc/sudoers
```

__View accounts with UID 0:__

```
# awk -F: '($3 == "0") {print}' /etc/passwd

# egrep ':0+' /etc/passwd
```

__View root authorized SSH key authentications:__

```
# cat /root/.ssh/authorized_keys
```

__List of files opened by user:__

```
# lsof -u <USER NAME>
```

__View the root user bash history:__

```
# cat /root/.bash_history
```


#### Network Information

__View network interfaces:__

```
# ifconfig
```

__View network connections:__

```
# netstat -antup

# netstat -plantux
```

__View listening ports:__

```
# netstat -nap
```

__View routes:__

```
# route
```

__View arp table:__

```
# arp -a
```

__List of processes listening to ports:__

```
# lsof -i
```

#### Service Information


__View processes:__

```
# ps -aux
```

__List of loaded modules:__

```
# lsmod
```

__List of open files:__

```
# 
```

__List of open files, using the network__

```
# lsof -nPi | cut -f 1 -d " " | uniq | tail -n +2
```

__List of open files on specific process:__

```
# lsof -c <SERVICE NAME>
```

__Get all open files of a specific process ID:__

```
# lsof -p <PID>
```

__List of unlinked processes running:__

```
# lsof +L1
```

__Get path of suspicious process PID:__

```
# ls -al /proc/<PID>/exe
```

__Save fle for further malware binary analysis:__

```
# cp /proc/<PID>/exe > /<SUSPICIOUS FILE NAME TO SAVE>.elf
```

__Monitor logs in real-time:__

```
# less +F /var/log/messages
```

__List services:__

```
# chkconfig --list
```

#### Policy, Patch and Settings Information

__View pam.d files:__

```
# cat /etc/pam.d/common*
```

#### Autorun and Autoload Information:

__List cron jobs:__

```
# crontab -l
```

__List cron jobs by root and other UID 0 accounts:__

```
# crontab -u root -l
```

__Review for unusual cron jobs:__

```
# cat /etc/crontab

# ls /etc/cron.*
```

#### Logs

__View root user command history:__

```
# cat /root/.*history
```

__View last logins:__

```
# last
```
