# PCDC - Microsoft SQL

> John Hammond | April 13th, 2019

------------------


To check to see if `xp_cmdshell` is enabled (it should be disabled), run this

```
EXEC SP_CONFIGURE 'show advanced option', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'xp_cmdshell'; 
```

To check to see if the `sa` account is enabled (it should disabled), run this

```
USE MASTER 
GO 
SELECT name, is_disabled 
FROM sys.sql_logins 
WHERE principal_id = 1; 
```

Check old an vulnerable databases:

```
SELECT name from sysdatabases where name like 'AdventureWorks%'; 
SELECT name from sysdatabases where name like 'Northwind%'; 
```

To determine the Server Authentication Mode, execute the following: (If the config_value does not equal "Windows NT Authentication", this is a finding)

```
EXEC XP_LOGINCONFIG 'login mode' 
```



Obtain a list of SQL Server DBAs or other administrative accounts. Run the following SQL script to check all users’ permissions: (If any DBA or administrative objects are owned by non-DBA or non-administrative accounts, this is a finding) 

```
SELECT SP1.[name] AS 'Login', 'Role: ' + SP2.[name] COLLATE DATABASE_DEFAULT AS 'ServerPermission' 
FROM sys.server_principals SP1 
JOIN sys.server_role_members SRM 
ON SP1.principal_id = SRM.member_principal_id 
JOIN sys.server_principals SP2 
ON SRM.role_principal_id = SP2.principal_id 
UNION ALL 
SELECT SP.[name] AS 'Login' , SPerm.state_desc + ' ' + SPerm.permission_name COLLATE DATABASE_DEFAULT AS 'ServerPermission' 
FROM sys.server_principals SP 
JOIN sys.server_permissions SPerm 
ON SP.principal_id = SPerm.grantee_principal_id 
ORDER BY [Login], [ServerPermission] 
```

**There are plenty more of these in the Microsoft SQL Server Instance STIGs, but I currently do not have the initiative to include them.***