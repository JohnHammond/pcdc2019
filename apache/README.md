Apache
===========

Check for things like `/phpmyadmin`.

If that is accessible, set it to only be viewed from `localhost` in `.htaccess`

If your pages `include()` files, try and move them to files to files outside of the public directory. Like `/var/www`, just up a directory from  `/var/www/html`.

Check Version
------

```
apache2 -v
```

If you are running Apache 2.4, you can use this syntax in `.htaccess` to allow a folder only to be acce