<?php
declare(strict_types=1);
namespace LFreeze\Crypto\Methods;

use InvalidArgumentException;

final class OpenSsl
{
    private const KEY_BYTES = 32; // 256-bit キー長
    private const NONCE_BYTES = 16;  // 128-bit IV長

    public static function encrypt(string $message, string $key, string $iv = null): string
    {

        if ($iv === null) {
            $iv = openssl_random_pseudo_bytes(self::NONCE_BYTES);
        } else {
            self::validateIV($iv);
        }

        self::validateKey($key);

        $cipherText = openssl_encrypt($message, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        if ($cipherText === false) {
            throw new Exception('Encryption failed');
        }

        return base64_encode($iv . $cipherText);
    }

    public static function decrypt(string $cipherText, string $key, string $iv = null): ?string
    {

        if ($iv === null) {
            // IVが指定されない場合、IVの長さ分を取り出す
            $decoded = base64_decode($cipherText, true);
            if ($decoded === false) {
                return null; // Base64 decoding failed
            }

            $iv = substr($decoded, 0, self::NONCE_BYTES);
        } else {
            self::validateIV($iv);
        }

        self::validateKey($key);

        $decoded = base64_decode($cipherText, true);
        if ($decoded === false) {
            return null; // Base64 decoding failed
        }


        
        $plainText = openssl_decrypt(substr($decoded, self::NONCE_BYTES), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        if ($plainText === false) {
            return null; // Decryption failed
        }

        return $plainText;
    }

    private static function validateKey(string $key): void
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException('Invalid key length. Specified length '.self::KEY_BYTES . '. Given length '. strlen($key));
        }
    }

    private static function validateIV(string $iv): void
    {
        if (strlen($iv) !== self::NONCE_BYTES) {
            throw new InvalidArgumentException('Invalid IV length. Specified length '.self::NONCE_BYTES . '. Given length '. strlen($iv));
        }
    }
}

// 使用例
/*
$key = "ThisIsMySecretKey1234567890123456"; // 生のキーを指定（32バイト）
$message = "This is a secret message.";
$iv = "stringstringstringstringstringstringstringstring"; // 生の IV を指定（32バイト）

try {
    $cipherText = EncryptionLibrary::encrypt($message, $key, $iv);
    $decryptedMessage = EncryptionLibrary::decrypt($cipherText, $key, $iv);

    if ($decryptedMessage !== null) {
        echo "Decrypted message: $decryptedMessage\n";
    } else {
        echo "Decryption failed.\n";
    }
} catch (InvalidArgumentException $e) {
    echo "Validation error: " . $e->getMessage() . "\n";
}
*/