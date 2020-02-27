<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\Cipher;
use Authwave\InsecureProtocolException;
use Authwave\Token;
use PHPUnit\Framework\MockObject\MockObject;
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

// All AuthUris MUST be served over HTTPS, with the one exception of localhost.
// But it should still default to HTTPS on localhost.
	public function testGetAuthUriHostnameLocalhostHttpsByDefault() {
		$cipher = self::createMock(Cipher::class);
		$token = self::createMock(Token::class);
		$token->method("generateCipher")
			->willReturn($cipher);

		$sut = new Authenticator($token, "localhost");
		$authUri = $sut->getAuthUri();
		self::assertStringStartsWith(
			"https://localhost",
			$authUri
		);
	}

// We should be able to set the scheme to HTTP for localhost hostname only.
	public function testGetAuthUriHostnameLocalhostHttpAllowed() {
		$cipher = self::createMock(Cipher::class);
		$token = self::createMock(Token::class);
		$token->method("generateCipher")
			->willReturn($cipher);

		$sut = new Authenticator($token, "http://localhost");
		$authUri = $sut->getAuthUri();
		self::assertStringStartsWith(
			"http://localhost",
			$authUri
		);
	}

// We should NOT be able to set the scheme to HTTP for other hostnames.
	public function testGetAuthUriHostnameNotLocalhostHttpNotAllowed() {
		$cipher = self::createMock(Cipher::class);
		$token = self::createMock(Token::class);
		$token->method("generateCipher")
			->willReturn($cipher);

		self::expectException(InsecureProtocolException::class);
		new Authenticator($token, "http://localhost.com");
	}
}