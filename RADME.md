[![Packagist Version](https://img.shields.io/packagist/v/l-freeze/crypto)](https://packagist.org/packages/l-freeze/crypto)
[![Test](https://github.com/l-freeze/php-crypto/actions/workflows/ci.yaml/badge.svg)](https://github.com/l-freeze/php-crypto/actions/workflows/ci.yaml)

# why?

- iv指定した場合の暗号化で常に同じ結果になるように。
ただしivを指定しない方法で利用する方がセキュリティは高くなる

- sodium/opensslに対応

- sodium/opensslいずれかのライブラリーが使えれば良い為、requiredにはそれらを記載していない


# Usage

install
```
composer require l-freeze/crypto
```
or
```
docker run --rm --interactive --tty --volume $PWD:/app   --user $(id -u):$(id -g)  composer require l-freeze/crypto
```

example
```php
//index.php
<?php
declare(strict_types=1);
require('vendor/autoload.php');

use LFreeze\Crypto\Crypto;

//Encryption by Sodium
Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);

$key ='EncryptionKey#MustStringLength32';
$iv = 'InitializationVector::24';


$resource = <<<EOT
=========================
[SODIUM: Specified iv -> FixedEncryptedString]
=========================

EOT;

$encrypted = Crypto::encrypt($resource, $key, $iv);
print_r($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key, $iv);
print_r($decrypted);
```

other: https://github.com/l-freeze/php-crypto/blob/master/example.php