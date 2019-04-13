#!/bin/bash

RED=`tput setaf 1`                          # code for red console text
GREEN=`tput setaf 2`                        # code for green text
YELLOW=`tput setaf 3`                       # code for yellow text
NC=`tput sgr0`                              # Reset the text color

echo "$GREEN[*] V-2225: Checking to make sure there is no access to shell programs... $NC"
grep "Action" /usr/local/apache2/conf/httpd.conf 
grep "AddHandler" /usr/local/apache2/conf/httpd.conf 



echo "$GREEN[*] V-2246: Checking apache verions.. (Should be 2.2.31 or more!) $NC"
httpd -v
httpd2 -v



echo "$GREEN[*] V-2255: Checking for htpasswd file... $NC"
find / -name htpasswd 2>/dev/null
echo "$GREEN[*] V-2255: Make sure permissions are chmod 550!!... $NC"
ls -l $(find / -name htpasswd 2>/dev/null)



echo "$GREEN[*] V-2256: Checking for .htaccess files... $NC"
find / -name .htaccess 2>/dev/null
echo "$GREEN[*] V-2255: Make sure permissions are chmod 660!!... $NC"
ls -l $(find / -name .htaccess 2>/dev/null)



echo "$GREEN[*] V-2230: Detecting possible backup files... $NC"
find / -name “*.bak” -print 2>/dev/null
find / -name “*.*~” -print 2>/dev/null
find / -name “*.old” -print 2>/dev/null


