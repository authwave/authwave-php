<?php
namespace Authwave\Test;

use Authwave\InitVector;
use Authwave\Token;
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
}