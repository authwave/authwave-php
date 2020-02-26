<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\Cipher;
use Authwave\Token;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase {
	public function testGetAuthUriHostname() {
		$cipher = self::createMock(Cipher::class);
		$token = self::createMock(Token::class);
		$token->method("generateCipher")
			->willReturn($cipher);

		$sut = new Authenticator($token, "example.com");
		$authUri = $sut->getAuthUri();
		self::assertStringStartsWith(
			"https://example.com",
			$authUri
		);
	}
}