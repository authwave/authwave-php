<?php
namespace Authwave\Test;

use Authwave\Token;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase {
	public function testGenerateCipherSameForSameToken() {
		$token = new Token(
			"test-key",
			"test-secret"
		);

		$cipher1 = $token->generateCipher();
		$cipher2 = $token->generateCipher();

		self::assertSame($cipher1, $cipher2);
	}

	public function testGenerateCipherDifferentForDifferentTokenSameDetails() {
		$key = "test-key";
		$secret = "test-secret";
		$token1 = new Token($key, $secret);
		$token2 = new Token($key, $secret);
		$cipher1 = $token1->generateCipher();
		$cipher2 = $token2->generateCipher();

		self::assertNotSame($cipher1, $cipher2);
	}
}