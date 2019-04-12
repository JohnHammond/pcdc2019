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


-----------------

I have not yet made effort to find means to harden or secure OrangeHRM.