<?php
declare(strict_types=1);
require('vendor/autoload.php');

use LFreeze\Crypto\Crypto;

//SODIUM
Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);
$key ='sdfagjkdls;rj4jejkjskljfdfafafda';
$iv = 'jakfjksaljfklajskdljfkla';
$resource = '元の文字列';

//iv指定の場合は常に同じ暗号化に
echo <<<EOT
=========================
[SODIUM: Specified iv]
=========================
EOT;

var_dump($resource);
$encrypted = Crypto::encrypt($resource, $key, $iv);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key, $iv);
var_dump($decrypted);
$encrypted = Crypto::encrypt($resource, $key, $iv);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key, $iv);
var_dump($decrypted);

//iv未指定の場合は重複しない暗号化
echo <<<EOT
=========================
[SODIUM: unSpecified iv]
=========================

EOT;
var_dump($resource);
$encrypted = Crypto::encrypt($resource, $key);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key);
var_dump($decrypted);
$encrypted = Crypto::encrypt($resource, $key);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key);
var_dump($decrypted);

//OPENSSL
Crypto::setcryptoMethod(Crypto::METHOD_OPENSSL);
$key ='sdfagjkdls;rj4jejkjskljfdfafafda';
$iv = 'jdslkafklakfjksd';
$resource = <<<EOT
暗号化する文字列。
長くてもOK。
プライバシー的に保護する必要な情報。

EOT;

//iv指定の場合は常に同じ暗号化に
echo <<<EOT
=========================
[OPENSSL: Specified iv]
=========================

EOT;
var_dump($resource);
$encrypted = Crypto::encrypt($resource, $key, $iv);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key, $iv);
var_dump($decrypted);
$encrypted = Crypto::encrypt($resource, $key, $iv);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key, $iv);
var_dump($decrypted);

//iv未指定の場合は重複しない暗号化
echo <<<EOT
=========================
[OPENSSL: Unspecified iv]
=========================

EOT;
var_dump($resource);
$encrypted = Crypto::encrypt($resource, $key);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key);
var_dump($decrypted);
$encrypted = Crypto::encrypt($resource, $key);
var_dump($encrypted);
$decrypted = Crypto::decrypt($encrypted, $key);
var_dump($decrypted);

