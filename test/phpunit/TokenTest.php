<?php
namespace Authwave\Test;

use Authwave\InitVector;
use Authwave\InvalidUserDataSerializationException;
use Authwave\ResponseCipherDecryptionException;
use Authwave\Token;
use Authwave\UserData;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase {
	public function testGenerateRequestCipherSameForSameToken() {
		$token = new Token(
			"test-key",
		);

		$cipher1 = $token->generateRequestCipher();
		$cipher2 = $token->generateRequestCipher();

		self::assertSame($cipher1, $cipher2);
	}

	public function testGenerateRequestCipherDifferentForDifferentTokenSameDetails() {
		$key = "test-key";
		$token1 = new Token($key);
		$token2 = new Token($key);
		$cipher1 = $token1->generateRequestCipher();
		$cipher2 = $token2->generateRequestCipher();

		self::assertNotSame($cipher1, $cipher2);
	}

	public function testGetIv() {
		$iv = self::createMock(InitVector::class);
		$sut = new Token("", null, $iv);
		self::assertSame($iv, $sut->getIv());
	}

	public function testDecryptResponseCipherInvalid() {
		$cipher = "0123456789abcdef";
		$sut = new Token("test-key");
		self::expectException(ResponseCipherDecryptionException::class);
		$sut->decryptResponseCipher($cipher);
	}

	public function testDecryptResponseCipherBadJson() {
		$key = uniqid("test-key-");
		$secretIv = self::createMock(InitVector::class);
		$secretIv->method("getBytes")
			->willReturn(str_repeat("0", 16));
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")
			->willReturn(str_repeat("f", 16));
		$cipher = openssl_encrypt(
			"{badly-formed: json]",
			Token::ENCRYPTION_METHOD,
			implode("|", [$key, $secretIv->getBytes()]),
			0,
			$iv->getBytes()
		);
		$cipher = base64_encode($cipher);
		$sut = new Token($key, $secretIv, $iv);
		self::expectException(InvalidUserDataSerializationException::class);
		$sut->decryptResponseCipher($cipher);
	}

	public function testDecryptResponseCipher() {
		$clientKey = uniqid("test-key-");
// SecretIv is stored in the client application's session only.
		$secretIv = self::createMock(InitVector::class);
		$secretIv->method("getBytes")
			->willReturn(str_repeat("0", 16));
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")
			->willReturn(str_repeat("f", 16));

		$uuid = "aabb-ccdd-eeff";
		$email = "user@example.com";
		$serialized = serialize((object)[
			"uuid" => $uuid,
			"email" => $email,
			"fields" => (object)[
				"example1" => "value1",
			]
		]);

		$cipher = openssl_encrypt(
			$serialized,
			Token::ENCRYPTION_METHOD,
			$clientKey,
			0,
			$secretIv->getBytes()
		);
		$cipher = base64_encode($cipher);
		$sut = new Token($clientKey, $secretIv, $iv);
		$userData = $sut->decryptResponseCipher($cipher);
		self::assertInstanceOf(UserData::class, $userData);
		self::assertEquals($uuid, $userData->getUuid());
		self::assertEquals($email, $userData->getEmail());
	}
}