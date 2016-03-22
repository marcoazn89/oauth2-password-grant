Installation
-------------
    composer require marcoazn89/oauth2-password-grant:1.0

Generate your keys
--------------------
    openssl genrsa -out oauth-key.pem 1024
    openssl rsa -in oauth-key.pem -pubout > oauth-key.pub

OAuth2 configuration
--------------------
```php
'auth' => [
    'private-key' => 'file://' . __DIR__ .'/../oauth-key.pem',
    'public-key' => 'file://' . __DIR__ .'/../oauth-key.pub',
    'expiration' => 604800
],
```
