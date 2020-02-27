<?php
namespace Authwave\Test;

use Authwave\AuthUri;
use Authwave\InitVector;
use Authwave\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthUriTest extends TestCase {
	public function testAuthUriHttps() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("https://example.com");
		$token = self::createMock(Token::class);

		$sut = new AuthUri($baseUri, $token, "");
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
		$token->method("generateCipher")
			->willReturn($mockCipherValue);
		$token->method("getIv")
			->willReturn($iv);

		$returnPath = "/examplePage";
		$sut = new AuthUri($baseUri, $token, $returnPath);
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
			base64_encode($returnPath),
			$queryParts[AuthUri::QUERY_STRING_RETURN_PATH]
		);
	}
}