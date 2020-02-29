<?php
namespace Authwave\Test;

use Authwave\AuthUri;
use Authwave\InitVector;
use Authwave\InsecureProtocolException;
use Authwave\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthUriTest extends TestCase {
	public function testAuthUriHttps() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("https://example.com");
		$token = self::createMock(Token::class);

		$sut = new AuthUri($token, "", $baseUri);
		self::assertEquals(
			"https",
			$sut->getScheme()
		);
	}

// All AuthUris MUST be served over HTTPS, with the one exception of localhost.
// But it should still default to HTTPS on localhost.
	public function testGetAuthUriHostnameLocalhostHttpsByDefault() {
		$token = self::createMock(Token::class);
		$sut = new AuthUri($token, "/", "localhost");
		self::assertStringStartsWith(
			"https://localhost",
			$sut
		);
	}

// We should be able to set the scheme to HTTP for localhost hostname only.
	public function testGetAuthUriHostnameLocalhostHttpAllowed() {
		$token = self::createMock(Token::class);
		$sut = new AuthUri($token, "/", "http://localhost");
		self::assertStringStartsWith(
			"http://localhost",
			$sut
		);
	}

// We should NOT be able to set the scheme to HTTP for other hostnames.
	public function testGetAuthUriHostnameNotLocalhostHttpNotAllowed() {
		$token = self::createMock(Token::class);
		self::expectException(InsecureProtocolException::class);
		new AuthUri($token, "/", "http://localhost.com");
	}

	public function testAuthUriHttpsInferred() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("example.com");
// Note on the line above, no scheme is passed in - we must assume https.
		$token = self::createMock(Token::class);

		$sut = new AuthUri($token, "/", $baseUri);
		self::assertEquals(
			"https",
			$sut->getScheme()
		);
	}

	public function testQueryString() {
		$mockCipherValue = str_repeat("f", 16);
		$mockIvValue = str_repeat("0", 16);
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")
			->willReturn($mockIvValue);

		$baseUri = self::createMock(UriInterface::class);
		$token = self::createMock(Token::class);
		$token->method("generateRequestCipher")
			->willReturn($mockCipherValue);
		$token->method("getIv")
			->willReturn($iv);

		$returnPath = "/examplePage";
		$sut = new AuthUri($token, $returnPath, $baseUri);
		parse_str($sut->getQuery(), $queryParts);

		self::assertEquals(
			$mockCipherValue,
			$queryParts[AuthUri::QUERY_STRING_CIPHER],
		);

		self::assertEquals(
			$mockIvValue,
			$queryParts[AuthUri::QUERY_STRING_INIT_VECTOR]
		);

		self::assertEquals(
			$returnPath,
			$queryParts[AuthUri::QUERY_STRING_CURRENT_PATH]
		);
	}
}