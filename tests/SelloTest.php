<?php

use PHPUnit\Framework\TestCase;
use Webneex\SelloCFDI\Sello;

final class SelloTest extends TestCase {

    public function testCSD() {

        $sello = new Sello;
        $sello->setPublicKey(file_get_contents(__DIR__ . '/resources/30001000000400002333.cer'));
        $sello->setPrivateKey(file_get_contents(__DIR__ . '/resources/CSD_MARIA_WATEMBER_TORRES_WATM640917J45_20190528_175656.key'), '12345678a');

        $this->assertEquals('feea984057fd2150348af8d6ab8762ab', md5($sello->getPrivateKey(true)));

        $this->assertEquals('d8d19f731f5e9cda1751d902fba1a456', md5($sello->getPrivateKey(false)));

        $this->assertEquals('30001000000400002333', $sello->getPublicKeySerial());

        $this->assertEquals('WATM640917J45', $sello->getPublicKeyRFC());

        $this->assertTrue($sello->isValid(new DateTime('2020-01-01')));

        $this->assertFalse($sello->isValid(new DateTime('2019-05-29 19:31:34')));
        $this->assertTrue($sello->isValid(new DateTime('2019-05-29 19:31:35')));

        $this->assertFalse($sello->isValid(new DateTime('2023-05-29 19:31:36')));
        $this->assertTrue($sello->isValid(new DateTime('2023-05-29 19:31:34')));

        $this->assertFalse($sello->isFIEL());


        $signature = $sello->sign('test', OPENSSL_ALGO_SHA1);

        $this->assertEquals('HJs2qVRpa4YkO94xBPBtXgfV126dVWAhEQ/qfemM6JdTS1qmX3Da7ugJA/J0S7oWHqWLXvkHMTQMDpygxm0cnhPuOqzKI7t+LH7o3bYDFJtU/Vr+8tm6yv+MSIjXNrnLnqvbaYYflqM5MdptYTB84RsLEzlbGGG0pR+w9dYcWcKpsKAHui9Da+HmXttVa9Y/7fXvjECWtciZ2kRGOWmNnYlYLRnYbKUu/G9eks2nmyRsT0D24ybtNx6mCW3ExAn8crYSenisBw5QIKBk1SqiCowBfjY6ZT3q3qHxRM7qOkJKSQB0AljI6aTLpKSTb+D8baAhG7STNoaoiOkziacdgA==', $signature);

        $this->assertTrue($sello->verify($signature, 'test', OPENSSL_ALGO_SHA1));
        $this->assertFalse($sello->verify($signature, 'test', OPENSSL_ALGO_SHA256));
        $this->assertFalse($sello->verify($signature, 'wrong', OPENSSL_ALGO_SHA1));
    }

    public function testFIEL() {
        $sello = new Sello;
        $sello->setPublicKey(file_get_contents(__DIR__ . '/resources/watm640917j45.cer'));

        $this->assertEquals('30001000000400002308', $sello->getPublicKeySerial());

        $this->assertEquals('WATM640917J45', $sello->getPublicKeyRFC());

        $this->assertTrue($sello->isValid(new DateTime('2020-01-01')));

        $this->assertFalse($sello->isValid(new DateTime('2019-05-28 21:57:31')));
        $this->assertTrue($sello->isValid(new DateTime('2019-05-28 21:57:32')));

        $this->assertFalse($sello->isValid(new DateTime('2023-05-27 21:57:33')));
        $this->assertTrue($sello->isValid(new DateTime('2023-05-27 21:57:32')));

        $this->assertTrue($sello->isFIEL());

    }
}
