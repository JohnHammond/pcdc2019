#!/usr/bin/env python

import sys
import requests

import re

ip_address = '192.168.0.75'
previous_password = 'johnwins'

login_url = 'https://%s/index.php' % ip_address


s = requests.Session()
r = s.get(login_url, verify = False)



# Scrape out the CSRF...
csrf = re.findall('__csrf_magic\' value="(.*)"', r.text)[0]
# print csrf

# Login...
r = s.post(login_url, data = { \
    "__csrf_magic" : csrf,
    "usernamefld" : "admin",
    "passwordfld" : previous_password,
    "login" : "Sign In"
 })


# print r.text

change_admin_url = 'https://%s/system_usermanager.php?act=edit&userid=0' % ip_address


r = s.get(change_admin_url, verify = False)
# print r.text

csrf = re.findall('__csrf_magic\' value="(.*)"', r.text)[0]
# print csrf

new_password = 'johnwins'

change_data = {
    "__csrf_magic" : csrf,
    'usernamefld': 'admin',
    'passwordfld1': new_password,
    'passwordfld2': new_password,
    'expires': '',
    'webguicss': 'pfSense.css',
    'webguifixedmenu': '',
    'webguihostnamemenu': '',
    'dashboardcolumns': '2',
    'groups[]': 'admins',
    'authorizedkeys': '',
    'ipsecpsk': '',
    'act': '',
    'userid': '0',
    'privid': '',
    'certid': '',
    'utype': 'system',
    'oldusername': 'admin',
    'save': 'Save',
}


r = s.post(change_admin_url, data = change_data )

# print r.text


'''
6037078858@vtext.com
smtp.gmail.com
pvjraiders@gmail.com
Welcome@123
465
20
pvjpfsense@bsidesdc.com
'''

# ---------------------------------------------------------------

# Send text messages for updates
notifications_url = 'https://%s/system_advanced_notifications.php' % ip_address

r = s.get(change_admin_url, verify = False)
# print r.text

csrf = re.findall('__csrf_magic\' value="(.*)"', r.text)[0]
# print csrf

data = {
    "__csrf_magic" : csrf,
    'smtpipaddress': 'smtp.gmail.com',
    'smtpport': '465',
    'smtptimeout': '20',
    'smtpssl': 'yes',
    'smtpfromaddress': 'pvjpfsense@bsidesdc.com',
    'smtpnotifyemailaddress': '6037078858@vtext.com',
    'smtpusername': 'pvjraiders@gmail.com',
    'smtppassword': 'Welcome@123',
    'smtppassword_confirm': 'Welcome@123',
    'smtpauthmech': 'PLAIN',
    'name': 'pfSense-Growl',
    'notification_name': 'pfSense growl alert',
    'ipaddress': '',
    'password': '',
    'password_confirm': '',
    'save': 'Save',
}


r = s.post(notifications_url, data = change_data )
print r.text