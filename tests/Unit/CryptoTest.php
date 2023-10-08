<?php
declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use LFreeze\Crypto\Crypto;
use InvalidArgumentException;

class CryptoTest extends TestCase
{
    public function test_sodiumでiv未指定で暗号化すると暗号化結果は常に異なる(){

        Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);
        $key ='CryptoKeyString0123456789abcdefg';
        $resource = 'テストに使う文字列';
        
        $encrypted1 = Crypto::encrypt($resource, $key);
        $decrypted1 = Crypto::decrypt($encrypted1, $key);
        $encrypted2 = Crypto::encrypt($resource, $key);
        $decrypted2 = Crypto::decrypt($encrypted2, $key);
        $this->assertSame($resource, $decrypted1);
        $this->assertSame($resource, $decrypted2);
        $this->assertNotEquals($encrypted1, $encrypted2);
    }

    public function test_sodiumでiv指定で暗号化しすると暗号化結果は常に同じ(){

        Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);
        $key ='CryptoKeyString0123456789abcdefg';
        $iv = 'CryptoIvString0123456789';
        $resource = 'テストに使う文字列';
        
        $encrypted1 = Crypto::encrypt($resource, $key, $iv);
        $decrypted1 = Crypto::decrypt($encrypted1, $key, $iv);
        $encrypted2 = Crypto::encrypt($resource, $key, $iv);
        $decrypted2 = Crypto::decrypt($encrypted2, $key, $iv);
        $this->assertSame($resource, $decrypted1);
        $this->assertSame($resource, $decrypted2);
        $this->assertSame($encrypted1, $encrypted2);

    }


    public function test_opensslでiv未指定で暗号化しすると暗号化結果は常に異なる(){

        Crypto::setcryptoMethod(Crypto::METHOD_OPENSSL);
        $key ='CryptoKeyString0123456789abcdefg';
        $resource = 'テストに使う文字列';
        
        $encrypted1 = Crypto::encrypt($resource, $key);
        $decrypted1 = Crypto::decrypt($encrypted1, $key);
        $encrypted2 = Crypto::encrypt($resource, $key);
        $decrypted2 = Crypto::decrypt($encrypted2, $key);
        $this->assertEquals($resource, $decrypted1);
        $this->assertEquals($resource, $decrypted2);
        $this->assertNotEquals($encrypted1, $encrypted2);
    }

    public function test_opensslでiv指定で暗号化しすると暗号化結果は常に同じ(){

        Crypto::setcryptoMethod(Crypto::METHOD_OPENSSL);
        $key ='CryptoKeyString0123456789abcdefg';
        $iv = 'CryptoIvString01';
        $resource = 'テストに使う文字列';
        
        $encrypted1 = Crypto::encrypt($resource, $key, $iv);
        $decrypted1 = Crypto::decrypt($encrypted1, $key, $iv);
        $encrypted2 = Crypto::encrypt($resource, $key, $iv);
        $decrypted2 = Crypto::decrypt($encrypted2, $key, $iv);
        $this->assertEquals($resource, $decrypted1);
        $this->assertEquals($resource, $decrypted2);
        $this->assertEquals($encrypted1, $encrypted2);
    }

    public function test_sodiumで不正な長さのkey指定でエラー(){

        Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);
        $key ='BadCryptoKeyString';
        $resource = 'テストに使う文字列';
    
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('key');
        $encrypted1 = Crypto::encrypt($resource, $key);
    }

    public function test_sodiumで不正な長さのiv指定でエラー(){

        Crypto::setcryptoMethod(Crypto::METHOD_SODIUM);
        $key ='CryptoKeyString0123456789abcdefg';
        $iv ='BadIv';
        $resource = 'テストに使う文字列';
    
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('IV');
        $encrypted1 = Crypto::encrypt($resource, $key, $iv);
    }

    public function test_opensslで不正な長さのkey指定でエラー(){

        Crypto::setcryptoMethod(Crypto::METHOD_OPENSSL);
        $key ='BadCryptoKeyString';
        $resource = 'テストに使う文字列';
    
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('key');
        $encrypted1 = Crypto::encrypt($resource, $key);
    }

    public function test_opensslで不正な長さのiv指定でエラー(){

        Crypto::setcryptoMethod(Crypto::METHOD_OPENSSL);
        $key ='CryptoKeyString0123456789abcdefg';
        $iv ='BadIv';
        $resource = 'テストに使う文字列';
    
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('IV');
        
        $encrypted1 = Crypto::encrypt($resource, $key, $iv);
    }

}