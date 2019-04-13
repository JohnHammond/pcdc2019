# @Author: John Hammond
# @Date:   2019-04-13 14:17:09
# @Last Modified by:   John Hammond
# @Last Modified time: 2019-04-13 14:17:19


# Hide Apache2 version
echo "ServerSignature Off" >> /etc/apache2/apache2.conf
echo "ServerTokens Prod" >> /etc/apache2/apache2.conf

# Remove ETags
echo "FileETag None" >> /etc/apache2/apache2.conf

# Disable Directory Browsing
a2dismod -f autoindex

# Remove default page
echo "" > /var/www/html/index.html

# Secure root directory
echo "<Directory />" >> /etc/apache2/conf-available/security.conf
echo "Options -Indexes" >> /etc/apache2/conf-available/security.conf
echo "AllowOverride None" >> /etc/apache2/conf-available/security.conf
echo "Order Deny,Allow" >> /etc/apache2/conf-available/security.conf
echo "Deny from all" >> /etc/apache2/conf-available/security.conf
echo "</Directory>" >> /etc/apache2/conf-available/security.conf

# Secure html directory
echo "<Directory /var/www/html>" >> /etc/apache2/conf-available/security.conf
echo "Options -Indexes -Includes" >> /etc/apache2/conf-available/security.conf
echo "AllowOverride None" >> /etc/apache2/conf-available/security.conf
echo "Order Allow,Deny" >> /etc/apache2/conf-available/security.conf
echo "Allow from All" >> /etc/apache2/conf-available/security.conf
echo "</Directory>" >> /etc/apache2/conf-available/security.conf
  
# Use TLS only
sed -i "s/SSLProtocol all -SSLv3/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/apache2/mods-available/ssl.conf

# Use strong cipher suites
sed -i "s/SSLCipherSuite HIGH:\!aNULL/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/apache2/mods-available/ssl.conf

# Enable headers module
a2enmod headers

# Enable HttpOnly and Secure flags
echo "Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure" >> /etc/apache2/conf-available/security.conf

# Clickjacking Attack Protection
echo "Header always append X-Frame-Options SAMEORIGIN" >> /etc/apache2/conf-available/security.conf

# XSS Protection
echo "Header set X-XSS-Protection \"1; mode=block\"" >> /etc/apache2/conf-available/security.conf

# Enforce secure connections to the server
echo "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"" >> /etc/apache2/conf-available/security.conf

# MIME sniffing Protection
echo "Header set X-Content-Type-Options: \"nosniff\"" >> /etc/apache2/conf-available/security.conf

# Prevent Cross-site scripting and injections
echo "Header set Content-Security-Policy \"default-src 'self';\"" >> /etc/apache2/conf-available/security.conf

# Prevent DoS attacks - Limit timeout
sed -i "s/Timeout 300/Timeout 60/" /etc/apache2/apache2.conf

service apache2 restart