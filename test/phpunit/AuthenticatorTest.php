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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthenticatorTest extends TestCase {
	public function testConstructWithDefaultSessionNotStarted() {
		self::expectException(SessionNotStartedException::class);
		new Authenticator("test-key","/");
	}

	public function testConstructWithDefaultSession() {
		$_SESSION = [];
		new Authenticator("test-key", "/");
		self::assertArrayHasKey(
			Authenticator::SESSION_KEY,
			$_SESSION
		);
	}

	public function testIsLoggedInFalseByDefault() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"/"
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
		$currentPath = uniqid("/path/");

		$cipher = "example-cipher";
		$ivString = "example-iv";

		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")
			->willReturn($ivString);

		$token = self::createMock(Token::class);
		$token->method("generateRequestCipher")
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
			$currentPath,
			AuthUri::DEFAULT_BASE_URI,
			null,
			$redirectHandler
		);
		$sut->login($token);
	}

	public function testLoginDoesNothingWhenAlreadyLoggedIn() {
		$sessionData = self::createMock(SessionData::class);
		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::never())
			->method("redirect");

		$sut = new Authenticator(
			"test-key",
			"/",
			AuthUri::DEFAULT_BASE_URI,
			null,
			$redirectHandler
		);

		$sut->login();
	}

	public function testGetUuidThrowsExceptionWhenNotLoggedIn() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
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
			"/"
		);
		self::assertEquals($expectedUuid, $sut->getUuid());
	}

	public function testGetEmailThrowsExceptionWhenNotLoggedIn() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::expectException(NotLoggedInException::class);
		$sut->getEmail();
	}

	public function testGetEmail() {
		$expectedEmail = "example@example.com";

		$userData = self::createMock(UserData::class);
		$userData->method("getEmail")
			->willReturn($expectedEmail);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getUserData")
			->willReturn($userData);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertEquals($expectedEmail, $sut->getEmail());
	}

	public function testCompleteAuthNotLoggedIn() {
		$currentUri = "/?"
			. Authenticator::RESPONSE_QUERY_PARAMETER
			. "=0123456789abcdef";

		$_SESSION = [];
		self::expectException(NotLoggedInException::class);
		new Authenticator(
			"test-key",
			$currentUri
		);
	}

// When the remote provider redirects back to the client application, a query
// string parameter is provided containing encrypted user and config data.
// In this example, we make our own query string parameter, which will NOT
// decrypt properly, and should throw an exception to prevent unauthorised
// access.
	public function testCompleteAuth() {
		$currentUri = "/my-page?filter=example&"
			. Authenticator::RESPONSE_QUERY_PARAMETER
			. "=0123456789abcdef";

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getQuery() === "filter=example"
				&& $uri->getPath() === "/my-page"
			));
		$token = self::createMock(Token::class);

		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getToken")
			->willReturn($token);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];
		new Authenticator(
			"test-key",
			$currentUri,
			AuthUri::DEFAULT_BASE_URI,
			null,
			$redirectHandler
		);

		/** @var SessionData $newSessionData */
		$newSessionData = $_SESSION[Authenticator::SESSION_KEY];
		self::assertNotSame($sessionData, $newSessionData);
		self::assertInstanceOf(
			SessionData::class,
			$newSessionData
		);
		self::assertInstanceOf(
			UserData::class,
			$newSessionData->getUserData()
		);
	}
}