<?php
namespace Authwave\Test\ProviderUri;

use Authwave\InitVector;
use Authwave\ProviderUri\LoginUri;
use Authwave\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class LoginUriTest extends TestCase {
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
		$sut = new LoginUri(
			$token,
			$returnPath,
			$baseUri
		);
		parse_str($sut->getQuery(), $queryParts);

		self::assertEquals(
			$mockCipherValue,
			$queryParts[LoginUri::QUERY_STRING_CIPHER],
		);

		self::assertEquals(
			$mockIvValue,
			$queryParts[LoginUri::QUERY_STRING_INIT_VECTOR]
		);

		self::assertEquals(
			bin2hex($returnPath),
			$queryParts[LoginUri::QUERY_STRING_CURRENT_PATH]
		);
	}
}
