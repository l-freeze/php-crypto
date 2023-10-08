<?php
declare(strict_types=1);
namespace Lfreeze\Crypto\Methods;

use InvalidArgumentException;

final class Sodium
{
    private const KEY_BYTES = SODIUM_CRYPTO_SECRETBOX_KEYBYTES;
    private const NONCE_BYTES = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

    public static function encrypt(string $message, string $key, ?string $iv = null): string
    {
        if ($iv === null) {
            $iv = random_bytes(self::NONCE_BYTES);
        }

        $cipherText = sodium_crypto_secretbox($message, self::validateIV($iv), self::validateKey($key));

        return base64_encode($iv . $cipherText);
    }

    public static function decrypt(string $cipherText, string $key): ?string
    {
        $decoded = base64_decode($cipherText, true);
        if ($decoded === false) {
            return null; // Base64 decoding failed
        }

        if (strlen($decoded) < (self::NONCE_BYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
            return null; // Invalid cipher text
        }

        $iv = substr($decoded, 0, self::NONCE_BYTES);
        $cipherText = substr($decoded, self::NONCE_BYTES);

        $plainText = sodium_crypto_secretbox_open($cipherText, self::validateIV($iv), self::validateKey($key));
        if ($plainText === false) {
            return null; // Decryption failed
        }

        return $plainText;
    }
    
    private static function validateKey(string $key): string
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException('Invalid key length. Specified length '.self::KEY_BYTES . '. Given length '. strlen($key));
        }

        return $key;
    }

    private static function validateIV(string $iv): string
    {
        if (strlen($iv) !== self::NONCE_BYTES) {
            throw new InvalidArgumentException('Invalid IV length. Specified length '.self::NONCE_BYTES . '. Given length '. strlen($iv));
        }

        return $iv;
    }    
}

/*
// 使用例
$key = "ThisIsMySecretKey"; // 任意の文字列を指定
$message = "This is a secret message.";

$cipherText = Crypto::encrypt($message, $key);
$decryptedMessage = Crypto::decrypt($cipherText, $key);

if ($decryptedMessage !== null) {
    echo "Decrypted message: $decryptedMessage\n";
} else {
    echo "Decryption failed.\n";
}
*/