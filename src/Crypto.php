<?php
declare(strict_types=1);
namespace LFreeze\Crypto;
use LFreeze\Crypto\Methods\OpenSsl;
use LFreeze\Crypto\Methods\Sodium;

final class Crypto
{
    public const METHOD_SODIUM = 'sodium';
    public const METHOD_OPENSSL = 'openssl';
    

    private static $cryptoMethod = 'openssl';

    public static function setcryptoMethod(string $method): void
    {
        $allowedMethods = [ 
            self::METHOD_SODIUM,
            self::METHOD_OPENSSL
        ];
        if (!in_array($method, $allowedMethods)) {
            throw new InvalidArgumentException('Invalid crypto method');
        }

        self::$cryptoMethod = $method;
    }

    public static function encrypt(string $message, string $key, string $iv = null): string
    {
        if (self::$cryptoMethod === self::METHOD_OPENSSL) {
            return OpenSSL::encrypt($message, $key, $iv);
        } elseif (self::$cryptoMethod === self::METHOD_SODIUM) {
            return Sodium::encrypt($message, $key, $iv);
        } else {
            throw new InvalidArgumentException('Invalid crypto method');
        }
    }

    /**
     * $ivは渡さなくても動くけどね。形式的に渡すようにしている。
     */
    public static function decrypt(string $cipherText, string $key, string $iv = null): ?string
    {
        if (self::$cryptoMethod === self::METHOD_OPENSSL) {
            return OpenSSL::decrypt($cipherText, $key, $iv);
        } elseif (self::$cryptoMethod === self::METHOD_SODIUM) {
            return Sodium::decrypt($cipherText, $key, $iv);
        } else {
            throw new InvalidArgumentException('Invalid crypto method');
        }
    }
}
?>
