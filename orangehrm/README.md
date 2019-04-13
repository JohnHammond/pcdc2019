# PCDC - OrangeHRM

> John Hammond | April 13th, 2019

---------------

According to [an online demo](https://opensource-demo.orangehrmlive.com/), the latest version of OrangeHRM MAY be: `4.3`

It is open-source! [https://github.com/orangehrm/orangehrm](https://github.com/orangehrm/orangehrm)

Notes from: [https://www.cvedetails.com/vulnerability-list/vendor_id-6180/Orangehrm.html](https://www.cvedetails.com/vulnerability-list/vendor_id-6180/Orangehrm.html)

* Version 2.x is seemingly the most vulnerable
* Multiple SQL injection vulnerabilities ( via the `sortField` parameter to (1) `viewCustomers`, (2) `viewPayGrades`, or (3) `viewSystemUsers` in `symfony/web/index.php/admin/`)
	- `updateStatus` function in `lib/models/benefits/Hsp.php`, via the `hspSummaryId` in `plugins/ajaxCalls/haltResumeHsp.php`
	- via `id` parameter in `lib/controllers/CentralController.php`
* LFI (Local File Inclusion) in `index.php`


**2 public exploits** known:

* [https://packetstormsecurity.com/files/117925/OrangeHRM-2.7.1-rc.1-Cross-Site-Request-Forgery-SQL-Injection.html](https://packetstormsecurity.com/files/117925/OrangeHRM-2.7.1-rc.1-Cross-Site-Request-Forgery-SQL-Injection.html)
* [	](https://www.exploit-db.com/exploits/15232)


Upgrade OrangeHRM
-----------------

[https://docs.bitnami.com/bch/apps/orangehrm/administration/upgrade/](https://docs.bitnami.com/bch/apps/orangehrm/administration/upgrade/)

* Back up your current OrangeHRM database.

```
cd /opt/bitnami/mysql
bin/mysql -u root -p
```

* Create a new database and assign permissions to the user of the orangehrm database.

```
mysql> CREATE DATABASE bitnami_orangehrm_backup;
mysql> GRANT ALL PRIVILEGES ON bitnami_orangehrm_backup.* TO 'bn_orangehrm'@'localhost' IDENTIFIED BY 'PASSWORD';
mysql> exit;
```

* Create OrangeHRM tables in the new database:

```
bin/mysqldump -u root -p bitnami_orangehrm > /home/bitnami/ohrm_backup.sql
bin/mysql -u root -p -o bitnami_orangehrm_backup < /home/bitnami/ohrm_backup.sql
```

* Remove the actual content of the /opt/bitnami/apps/orangehrm/htdocs directory and uncompress the new version of OrangeHRM to the same location.

```
cd /opt/bitnami/apps/orangehrm
sudo rm -rf htdocs/
sudo unzip orangehrm-version.zip
mv orangehrm-version/ htdocs/
```

* Change the ownership of the files and their permissions:

```
chown -R bitnami:daemon /opt/bitnami/apps/orangehrm/htdocs/
chmod -R 775 upgrader/ lib/ symfony/
```

* Launch the upgrade wizard. Access it in the web browser by navigating to http://SERVER-IP/upgrader/web/index.php:

![https://docs.bitnami.com/images/img/apps/orangehrm/orangehrm-upgrade.png](https://docs.bitnami.com/images/img/apps/orangehrm/orangehrm-upgrade.png)

* Complete the fields as is shown in the image. The password is the same that you put in the “GRANT ALL PRIVILEGES” command. Follow the remaining instructions.

* Clean up and remove the old database and the backup file:

```
/opt/bitnami/mysql/bin/mysql -u root -p
mysql> DROP DATABASE bitnami_orangehrm_backup;
mysql> exit;
rm /home/bitnami/ohrm_backup.sql
```

