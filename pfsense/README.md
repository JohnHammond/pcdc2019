pfSense Hardening
=========


I am not well-versed with pfSense (at all) so this is just what I can track down and put together. 

__The default credentials:__


```
admin:pfsense
```

--------------

0. UPDATE THE BOX.
1. Change default password.
2. Check the rules already set up.

----------------

> Set the WebGUI to https.
> 
> Set the WebGUI to a different port than 443 (i usually use 444 :D ).
> 
> Disable the anti-lockout rule (under system–>advanced) and allow access only from a source you control.
> 
> Or even better: dont allow access to the webGUI at all besides via a VPN (OpenVPN comes to mind).
> 
> Run as few packages/services as possible.
