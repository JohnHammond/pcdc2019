# PCDC - Moodle

> John Hammond | April 13th, 2019

---------------

According to [Wikipedia](https://en.wikipedia.org/wiki/Moodle), the latest version of Moodle is: `3.6.3`

Notes from: [https://www.cvedetails.com/vulnerability-list/vendor_id-2105/product_id-3590/Moodle-Moodle.html](https://www.cvedetails.com/vulnerability-list/vendor_id-2105/product_id-3590/Moodle-Moodle.html)

* MANY vulnerabilities... mostly XSS
* SQL injection: [https://www.exploit-db.com/exploits/41828](https://www.exploit-db.com/exploits/41828)
* Multiple means to remote code execution with Metasploit modules/
	- [https://www.exploit-db.com/exploits/46551](https://www.exploit-db.com/exploits/46551)
	- [https://www.rapid7.com/db/modules/exploit/multi/http/moodle_cmd_exec](https://www.rapid7.com/db/modules/exploit/multi/http/moodle_cmd_exec)

-----------------------------


Tidbits from [https://docs.moodle.org/36/en/Security_recommendations](https://docs.moodle.org/36/en/Security_recommendations)

* Change the Password Policy in `Settings`->`Site administration` -> `Security` -> `Site Policies`
* Use `chkrootkit`
* Always use the secure forms setting
* Always set a MySQL root user password
* Turn off MySQL network access
* Use SSL, `httpslogins=yes`
* Disable guest access
* Place enrollment keys on all courses or set Course Enrollable = No for all courses
* Ensure the enrollment key hint is disabled (which it is by default) in `Administration` > `Site administration` > `Plugins` > `Enrollment` > `Self enrollment`.

-------------------

If you feel you are under attack, put the site in _Maintenance mode_.

Prevention
===========

* Regularly run the Security overview report (`Settings` > `Site administration` > `Reports` > `Security overview`).
* Use the Spam cleaner tool (`Settings` > `Site administration` > `Reports` > `Spam cleaner`) regularly to find spam.
* Use `rkhunter` on Linux, `RootkitRevealer` on Windows.
* Use `AppArmor` on Linux,  `EMET` on Windows.


To Upgrade:
=============

* [https://docs.moodle.org/36/en/Upgrading](https://docs.moodle.org/36/en/Upgrading)
* [https://docs.moodle.org/36/en/Git_for_Administrators](https://docs.moodle.org/36/en/Git_for_Administrators)

```
cd /path/to/your/webroot
git clone git://git.moodle.org/moodle.git                       
cd moodle
git branch -a                                                   
git branch --track MOODLE_36_STABLE origin/MOODLE_36_STABLE     
git checkout MOODLE_36_STABLE                                   
```

```
cd /path/to/your/moodle/
git pull
```

Etcetera
===============

* Set `register_globals` to off in your PHP settings (this is the default).
* Keep "Force users to login for profiles" **enabled** in `Site administration` > `Security` > `Site security settings` 
* Keep "Profiles for enrolled users only" **enabled** in `Site administration` > `Security` > `Site security settings`.
* Keep self-registration **disabled** (it's the default) in `Site administration` > `Plugins` > `Authentication` > `Manage authentication`
* Turn on HTTPS `Settings` > `Site administration` > `Security` > `HTTP security`

Site Security Settings
----------------

* __Protect usernames:__ true
* __Force users to login:__ true
* __Force users to login for profiles:__ true
* __Force users to login to view user pictures:__ true
* __Open to Google:__ false
* __Profile Visible Roles:__ none
* __Maximum Uploaded File Size:__ 
	- The Apache server setting `LimitRequestBody`
	- The PHP site settings `post_max_size` and `upload_max_filesize` in `php.ini`
	- `Settings` > `Site administration` > `Security` > `Site policies` > `Maximum uploaded file size`.
* __User quota__: set to false (The maximum number of bytes that a user can store in their own Private files area)
* __Allow EMBED and OBJECT tags__ false
* __Enable trusted content__ false
* __Maximum time to edit posts__ 1
* __Allow extended characters in usernames__: false
* __Keep tag name casing__: false
* __Profiles for enrolled users only:__ false
* __Cron execution via command line only__: true
* __Cron password for remote access__ SET A PASSWORD HERE
* __Account lockout__ enabled, threshold 2, etc
* __Password policy__ Password Length 14, digits, 1, lowercase 1, uppercase 1, etc..
* __Password rotation limit__ 100 (Here you can specify how often a user must change their password before they can re-use a previous password.)
* __Log out after password change__ true
* __User created token duration__ true (version 3.4 onward)
* __Group enrolment key policy__ true
* __Disable user profile images__ true
* __Email change confirmation__ true
* __Remember username__ false
* __Strict validation of required fields__ true
* Turn off public Guest access (unless you are sure you know how to use it) in `Site administration` > `Plugins` > `Enrolments` > `Manage enrol plugins` and `Hide its button` in `Site administration` > `Plugins` > `Authentication` > `Manage authentication` > `Guest login button`

--------------

Login failure notifications: `Settings` > `Site Administration` > `Security` > `Notifications`

* __Display login failures to__ admin account
* __Email login failures__