Palmetto Cyber Defense Competition
===================================

> John Hammond | April 13th, 2019

---------------

This repository aims to hold code and information to be beneficial to the PCDC competition, held on April 15th, 2019.

Prior to the game, we blue team players were given two documents:

* PCDC 2019 Blue Team Packet
* PCDC Prep Guide

In this README I will offer a synopsis of the valuable excerpts from each.

Background
---------

The idea behind this game is that we are supporting (/defending) services for the "Palmetto Cyber Defense College." We have fictional students and courses to handle.

Key IT Services
---------

* Moodle
* OrangeHR
* Zimbra

Known Technology
---------

```
Windows 7
Ubuntu
Tomcat
vsFTPd
File Zilla
Active Directory
Microsoft SQL
(E-Mail)
(Database)
```

Blue Team Packet
===============

* __Changes of domain user accounts need to be reported to the Gold Team.__
* E-mail access is found at: `mail.blueXX.pcdc.local`
* Accessing the game VMs is at: `https://vcsa01.gold.pcdc.local`

**Backup and recovery** e-mails should send an e-mail to: `Thomas.Lewis.IT@gold.pcdc.local`:

```
SUBJECT: Backup/Recovery Rest

Team #: 
Request:
Justification:
```

**Incident reporting** _WILL BE SCORED_. Send an e-mail to `Carolyn.Hayes.IT@gold.pctc.local`

```
SUBJECT: Incident Reporting

Team #:
Time(s) of Incident: 
Asset(s) Affected:
Source (IP Address) of Attack: 
Description of Attack/Incident:
Remediation/Plan to Resolve: 
```

__Injects__ that include multiple files should be compressed into a ZIP file, with the name:

```
<teamNumber>_<injectNumber>_<injectTitle>
```

Additional Tools
=============

[https://github.com/meitar/awesome-cybersecurity-blueteam](https://github.com/meitar/awesome-cybersecurity-blueteam)