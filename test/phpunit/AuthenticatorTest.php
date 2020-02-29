<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\AuthUri;
use Authwave\InitVector;
use Authwave\NotLoggedInException;
use Authwave\RedirectHandler;
use Authwave\SessionData;
use Authwave\SessionNotStartedException;
use Authwave\Token;
use Authwave\UserData;
use Gt\Session\Session;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthenticatorTest extends TestCase {
	public function testConstructWithDefaultSessionNotStarted() {
		self::expectException(SessionNotStartedException::class);
		new Authenticator(
			"test-key",
			"test-secret",
			"/",
		);
	}

	public function testConstructWithDefaultSession() {
		$_SESSION = [];
		new Authenticator(
			"test-key",
			"test-secret",
			"/",
		);
		self::assertArrayHasKey(
			Authenticator::SESSION_KEY,
			$_SESSION
		);
	}

	public function testIsLoggedInFalseByDefault() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/",
		);
		self::assertFalse($sut->isLoggedIn());
	}

	public function testIsLoggedInTrueWhenSessionDataSet() {
		$userData = self::createMock(UserData::class);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->expects(self::once())
			->method("getUserData")
			->willReturn($userData);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData
		];

		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/",
		);
		self::assertTrue($sut->isLoggedIn());
	}

	public function testLogoutClearsSession() {
		$sessionData = self::createMock(SessionData::class);
		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData
		];

		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/",
		);
		$sut->logout();
		self::assertEmpty($_SESSION);
	}

	public function testLoginRedirects() {
		$_SESSION = [];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getHost() === AuthUri::DEFAULT_BASE_URI
			));

		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/",
			AuthUri::DEFAULT_BASE_URI,
			null,
			$redirectHandler
		);
		$sut->login();
	}

	public function testLoginRedirectsLocalhost() {
		$_SESSION = [];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getScheme() === "http"
				&& $uri->getHost() === "localhost"
				&& $uri->getPort() === 8081
			));

		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/",
			"http://localhost:8081",
			null,
			$redirectHandler
		);
		$sut->login();
	}

	public function testLoginRedirectsWithCorrectQueryString() {
		$_SESSION = [];

		$key = uniqid("key-");
		$secret = uniqid("secret-");
		$currentPath = uniqid("/path/");

		$cipher = "example-cipher";
		$ivString = "example-iv";

		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")
			->willReturn($ivString);

		$token = self::createMock(Token::class);
		$token->method("generateCipher")
			->willReturn($cipher);
		$token->method("getIv")
			->willReturn($iv);

		$expectedQueryParts = [
			AuthUri::QUERY_STRING_CIPHER => $cipher,
			AuthUri::QUERY_STRING_INIT_VECTOR => $ivString,
			AuthUri::QUERY_STRING_CURRENT_PATH => $currentPath,
		];
		$expectedQuery = http_build_query($expectedQueryParts);

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getQuery() === $expectedQuery
			));

		$sut = new Authenticator(
			$key,
			$secret,
			$currentPath,
			AuthUri::DEFAULT_BASE_URI,
			null,
			$redirectHandler
		);
		$sut->login($token);
	}

	public function testGetUuidThrowsExceptionWhenNotLoggedIn() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/"
		);
		self::expectException(NotLoggedInException::class);
		$sut->getUuid();
	}

	public function testGetUuid() {
		$expectedUuid = uniqid("example-uuid-");

		$userData = self::createMock(UserData::class);
		$userData->method("getUuid")
			->willReturn($expectedUuid);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getUserData")
			->willReturn($userData);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];
		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/"
		);
		self::assertEquals($expectedUuid, $sut->getUuid());
	}
}