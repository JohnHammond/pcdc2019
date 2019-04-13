@echo off

:: John: These commands are from the BTFM
:: https://github.com/JohnHammond/blueteamfieldmanual

echo "Turning the firewall on..."
netsh advfirewall set currentprofile state on

echo "Turning all states on the firewall on..."
netsh advfirewall set currentprofile set allprofile state on

echo "Setting Firewall Log MaxFileSize to 4096..."
netsh advfirewall set allprofile logging maxfilesize 4096

echo "Setting Firewall Log to log DROPPED connections..."
netsh advfirewall set allprofile logging droppedconnections enable

echo "Setting Firewall Log to log ALLOWED connections..."
netsh advfirewall set allprofile logging allowedconnections enable

:: --------------------------------------------------------------------------

:: TCP 80, 443 - HTTP/HTTPS/Internet
:: TCP/UDP 53 - DNS
:: TCP/UDP 3389 - RDP
:: TCP 139, 445 - Samba
:: UDP 137, 138 - Samba
:: TCP/UDP 389 - LDAP

:: HTTP
echo "Allowing TCP Port 80 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 80 IN" dir=in action=allow protocol=TCP localport=80 enable=yes
echo "Allowing TCP Port 80 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 80 OUT" dir=out action=allow protocol=TCP localport=80 enable=yes

:: HTTPS
echo "Allowing TCP Port 443 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 443 IN" dir=in action=allow protocol=TCP localport=443 enable=yes
echo "Allowing TCP Port 443 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 443 OUT" dir=out action=allow protocol=TCP localport=443 enable=yes

:: DNS
echo "Allowing UDP Port 53 IN"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 53 IN" dir=in action=allow protocol=UDP localport=53 enable=yes
echo "Allowing UDP Port 53 OUT"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 53 OUT" dir=out action=allow protocol=UDP localport=53 enable=yes
echo "Allowing TCP Port 53 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 53 IN" dir=in action=allow protocol=TCP localport=53 enable=yes
echo "Allowing TCP Port 53 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 53 OUT" dir=out action=allow protocol=TCP localport=53 enable=yes

:: RDP
echo "Allowing UDP Port 3389 IN"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 3389 IN" dir=in action=allow protocol=UDP localport=3389 enable=yes
echo "Allowing UDP Port 3389 OUT"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 3389 OUT" dir=out action=allow protocol=UDP localport=3389 enable=yes
echo "Allowing TCP Port 3389 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 3389 IN" dir=in action=allow protocol=TCP localport=3389 enable=yes
echo "Allowing TCP Port 3389 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 3389 OUT" dir=out action=allow protocol=TCP localport=3389 enable=yes

:: Samba TCP
echo "Allowing TCP Port 139 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 139 IN" dir=in action=allow protocol=TCP localport=139 enable=yes
echo "Allowing TCP Port 139 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 139 OUT" dir=out action=allow protocol=TCP localport=139 enable=yes
echo "Allowing TCP Port 445 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 445 IN" dir=in action=allow protocol=TCP localport=445 enable=yes
echo "Allowing TCP Port 445 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 445 OUT" dir=out action=allow protocol=TCP localport=445 enable=yes

:: Samba UDP
echo "Allowing UDP Port 137 IN"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 137 IN" dir=in action=allow protocol=UDP localport=137 enable=yes
echo "Allowing UDP Port 137 OUT"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 137 OUT" dir=out action=allow protocol=UDP localport=137 enable=yes
echo "Allowing UDP Port 138 IN"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 138 IN" dir=in action=allow protocol=UDP localport=138 enable=yes
echo "Allowing UDP Port 138 OUT"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 138 OUT" dir=out action=allow protocol=UDP localport=138 enable=yes

:: LDAP
echo "Allowing UDP Port 389 IN"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 389 IN" dir=in action=allow protocol=UDP localport=389 enable=yes
echo "Allowing UDP Port 389 OUT"
netsh advfirewall firewall add rule name="PvJ Allow UDP Port 389 OUT" dir=out action=allow protocol=UDP localport=389 enable=yes
echo "Allowing TCP Port 389 IN"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 389 IN" dir=in action=allow protocol=TCP localport=389 enable=yes
echo "Allowing TCP Port 389 OUT"
netsh advfirewall firewall add rule name="PvJ Allow TCP Port 389 OUT" dir=out action=allow protocol=TCP localport=389 enable=yes
