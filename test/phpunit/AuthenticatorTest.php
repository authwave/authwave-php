<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\InsecureProtocolException;
use Authwave\Token;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase {
	public function testGetAuthUriHostname() {
		$token = self::createMock(Token::class);
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
		$token = self::createMock(Token::class);
		$sut = new Authenticator($token, "localhost");
		$authUri = $sut->getAuthUri();
		self::assertStringStartsWith(
			"https://localhost",
			$authUri
		);
	}

// We should be able to set the scheme to HTTP for localhost hostname only.
	public function testGetAuthUriHostnameLocalhostHttpAllowed() {
		$token = self::createMock(Token::class);
		$sut = new Authenticator($token, "http://localhost");
		$authUri = $sut->getAuthUri();
		self::assertStringStartsWith(
			"http://localhost",
			$authUri
		);
	}

// We should NOT be able to set the scheme to HTTP for other hostnames.
	public function testGetAuthUriHostnameNotLocalhostHttpNotAllowed() {
		$token = self::createMock(Token::class);
		self::expectException(InsecureProtocolException::class);
		new Authenticator($token, "http://localhost.com");
	}
}