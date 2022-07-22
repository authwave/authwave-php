<?php
namespace Authwave\Test;

use Authwave\InvalidUserDataSerializationException;
use Authwave\ResponseCipherDecryptionException;
use Authwave\Token;
use Authwave\ResponseData\UserData;
use Gt\Cipher\InitVector;
use Gt\Cipher\Key;
use Gt\Cipher\Message\DecryptionFailureException;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase {
	public function testGenerateRequestCipher_sameForSameToken():void {
		$token = new Token(str_repeat("0", 32));

		$cipher1 = $token->generateRequestCipher();
		$cipher2 = $token->generateRequestCipher();

		self::assertEquals($cipher1, $cipher2);
	}

	public function testGenerateRequestCipher_differentForDifferentTokenSameDetails():void {
		$key = str_repeat("0", 32);
		$token1 = new Token($key);
		$token2 = new Token($key);
		$cipher1 = $token1->generateRequestCipher();
		$cipher2 = $token2->generateRequestCipher();

		self::assertNotEquals($cipher1, $cipher2);
	}

	public function testGetIv():void {
		$iv = self::createMock(InitVector::class);
		$sut = new Token("", null, $iv);
		self::assertSame($iv, $sut->getIv());
	}

	public function testDecrypt_responseCipherInvalid() {
		$key = str_repeat("0", 32);
		$sut = new Token($key);
		self::expectException(DecryptionFailureException::class);
		$sut->decode("not a real cipher");
	}

	public function testDecryptResponseCipherBadJson() {
		$keyString = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$sessionIv = self::createMock(InitVector::class);
		$sessionIv->method("getBytes")
			->willReturn(str_repeat("a", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES));
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")
			->willReturn(str_repeat("f", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES));

		$nonce = $iv->getBytes();
		$manualCipherString = sodium_crypto_secretbox(
			"{badly-formed: json]",
			$nonce,
			$keyString,
		);
		$decryptedCipherString = sodium_crypto_secretbox_open($manualCipherString, $nonce, $keyString);

		$base64Cipher = base64_encode($manualCipherString);
		$sut = new Token($keyString, $sessionIv, $iv);
		self::expectException(InvalidUserDataSerializationException::class);
		$sut->decode($base64Cipher);
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
		$userData = $sut->decode($cipher);
		self::assertInstanceOf(UserData::class, $userData);
		self::assertEquals($uuid, $userData->getId());
		self::assertEquals($email, $userData->getEmail());
	}
}
