# PCDC - Zimbra

> John Hammond | April 13th, 2019

---------------

According to [Wikipedia](https://en.wikipedia.org/wiki/Zimbra), the latest version of Zimbra is: `8.8.11`

Notes from: [https://www.cvedetails.com/vulnerability-list/vendor_id-7863/Zimbra.html](https://www.cvedetails.com/vulnerability-list/vendor_id-7863/Zimbra.html)

* XSS, XXE, Directory Traversal...

There are **two** public exploits (and even a _Metasploit_ module) that can offer Remote Code Execution:

* [https://www.exploit-db.com/exploits/30085](https://www.exploit-db.com/exploits/30085)
* [https://www.exploit-db.com/exploits/30472](https://www.exploit-db.com/exploits/30472)


Secure Configuration
--------------

1. Make sure LDAP is supporting STARTTLS - should be set to "1":

```
zmlocalconfig ldap_starttls_supported
zmlocalconfig -e ldap_starttls_supported=1
```

2. Require interprocess security - should be set to 1:

```
zmlocalconfig zimbra_require_interprocess_security
zmlocalconfig -e zimbra_require_interprocess_security=1
```

3. Require secure LDAP from mailboxd - should be set to "true":

```
zmlocalconfig ldap_starttls_required
zmlocalconfig -e ldap_starttls_required=true
```

Avoid letting undesirable content into the ZCS platform altogether by:

Consider also setting zimbraMtaBlockedExtension to reject email with specific types of attachments. For example (using bash expansion for brevity):

```
# add/remove file name extensions as makes sense in your environment
zmprov "+zimbraMtaBlockedExtension "{bat,cmd,docm,exe,js,lnk,ocx,rar,vbs,vbx,c,cpp,sh,php,out,elf}
# optionally, warn the recipient about the blocked message
zimbraVirusWarnRecipient TRUE
```