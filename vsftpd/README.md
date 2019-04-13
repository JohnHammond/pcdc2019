Hardening FTP
===========

We can expect a Linux FTP machine. Update it to version `3.0.3`

The config file is typically at `/etc/vsftpd/vsftpd.conf` or `/etc/vsftpd.conf`.



Updating to 3.0.3
=========

Webpage:
[https://security.appspot.com/vsftpd.html](https://security.appspot.com/vsftpd.html)

Download: [https://security.appspot.com/downloads/vsftpd-3.0.3.tar.gz](https://security.appspot.com/downloads/vsftpd-3.0.3.tar.gz)

Anonymous Login
-------------

If it does not break the scorebot, turn off anonymous login.

```
anonymous_enable=NO
```


Limit to Anonymous ONLY
==============

If you WANT Anonymous login, and ONLY that, use below:

```
listen=NO
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=NO
```

You will need a user for this account:

```
useradd -c " FTP User" -d /var/ftp -r -s /sbin/nologin ftp
```

If you do this, ensure it is DOWNLOAD only (unless this breaks the scorebot). Run as root:  

```
# cd ~ftp
# find . \( -user ftp -a -type d \) -exec /bin/chown 0 {} \;
# find . \( -perm -002 -a ! \( \( -type l \) -o \( -type c \) \) -exec  /bin/chmod o-w {} \; \)
```


If you NEED to allow uploads,

```
# cd ~ftp
# mkdir -p ./pub/incoming
# chown 0 ./pub
# chown 0 ./pub/incoming
# chmod 755 ./pub
# chmod 733 ./pub/incoming
```


Other Settings
--------------

This is the root directory for a logged in session...

```
local_root=/ftp
```

Using an SSL config
------------------

Run command to create it:
```
openssl req -x509 -nodes -newkey rsa:1024 -keyout /etc/vsftpd/vsftpd.pem -out /
etc/vsftpd/vsftpd.pem
```

Sete it in the config file:

```
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
ssl_ciphers=ALL:-ADH:+HIGH:+MEDIUM:-LOW:-SSLv2:-EXP
rsa_cert_file=/etc/vsftpd/vsftpd.pem
```


Change Banner
--------

```
tftpd_banner=Welcome
```

Jailing FTP Users
--------------

````
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
````

The file `/etc/vsftpd.chroot_list` contains the list of jailed users one per line.


You would need to create this file:

```
ftp
```

Firewall now
------------

```
# iptables -I INPUT -p tcp --dport 20 -j ACCEPT
# iptables -I INPUT -p tcp --dport 21 -j ACCEPT
# iptables -I INPUT -p tcp --dport 64000:65535 -j ACCEPT
```


Turn on Logging
-------------

```
xferlog_enable=YES
xferlog_std_format=NO
xferlog_file=/var/log/vsftpd.log 
log_ftp_protocol=YES
# debug_ssl=YES # Unless you set up SSL...
```

Control Connections and Bandwidth
--------------

```
anon_max_rate=30000

# This is a tough cut off for PvJ... tune as needed
max_per_ip=3

# This is a tough cut off for PvJ... tune as needed
idle_session_timeout=20
```


Restart the service
---------

Any of these -- depending on what you system you might be on.

```
systemctl restart vsftpd
service vsfptd restart
/etc/init.d/vsftpd start
```

Check the configuration.

```
chkconfig vsftpd on
```





Known Vulnerabilities
=================

* [https://www.cvedetails.com/vulnerability-list/vendor_id-2041/product_id-3475/Beasts-Vsftpd.html](https://www.cvedetails.com/vulnerability-list/vendor_id-2041/product_id-3475/Beasts-Vsftpd.html)

* [https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor](https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor)

*