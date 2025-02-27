# jwt.local
## Configure VirtualHost
```bash
sudo vim /etc/apache2/sites-available/jwt.local.conf
```
```bash
<VirtualHost *:80>
    ServerAdmin admin@jwt.local
    ServerName www.jwt.local
    ServerAlias jwt.local
    DocumentRoot /var/www/jwt.local/public
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

## Add the host to the /etc/hosts
```bash
sudo vim /etc/hosts
```
```
127.0.0.1	www.jwt.local
```

## Add dependencies via composer
```bash
composer require "twig/twig:^3.0"
composer require twbs/bootstrap
```

## Link the twbs to the public director to the public directory
```bash
ln -sf /var/www/jwt.local/vendor/twbs/ /var/www/jwt.local/public/assets/twbs
```

## Set .htaccess for public directory
```bash
RewriteEngine On
RewriteBase /
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ index.php [QSA,L]
```

## Set .htaccess for public/api directory
```bash
RewriteEngine On
RewriteBase /api/
RewriteRule ^index\\.php$ - [QSA,L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /api/index.php [QSA,L]
```
