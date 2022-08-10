<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\NotLoggedInException;
use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\LoginUri;
use Authwave\RedirectHandler;
use Authwave\ResponseData\BaseResponseData;
use Authwave\SessionData;
use Authwave\SessionNotStartedException;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use Gt\Http\Uri;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AuthenticatorTest extends TestCase {
	public function testConstructWithDefaultSessionNotStarted() {
		self::expectException(SessionNotStartedException::class);
		new Authenticator(
			"test-key",
			"/"
		);
	}

	public function testConstructWithDefaultSession() {
		$_SESSION = [];
		new Authenticator(
			"test-key",
			"/"
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
			"/"
		);
		self::assertFalse($sut->isLoggedIn());
	}

	public function testIsLoggedInTrueWhenSessionDataSet() {
		$userData = self::createMock(UserResponseData::class);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->expects(self::once())
			->method("getData")
			->willReturn($userData);

		/** @noinspection PhpArrayWriteIsNotUsedInspection */
		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData
		];

		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertTrue($sut->isLoggedIn());
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
			LoginUri::QUERY_STRING_CIPHER => $cipher,
			LoginUri::QUERY_STRING_INIT_VECTOR => $ivString,
			LoginUri::QUERY_STRING_CURRENT_PATH => bin2hex($currentPath),
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
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
		$sut->login($token);
	}

	public function testGetUuid() {
		$exampleId = uniqid("example-id-");

		$userData = self::createMock(UserResponseData::class);
		$userData->method("getId")
			->willReturn($exampleId);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getData")
			->willReturn($userData);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertEquals($exampleId, $sut->getId());
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

		$userData = self::createMock(UserResponseData::class);
		$userData->method("getEmail")
			->willReturn($expectedEmail);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getData")
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

	public function testCompleteAuthNotAffectedByQueryString() {
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::never())
			->method("redirect");
		$_SESSION = [];

		new Authenticator(
			"test-key",
			"/example-path/?filter=something",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
	}

	public function testGetAdminUri() {
		$_SESSION = [];
		$auth = new Authenticator(
			"test-key",
			"/example-path",
			BaseProviderUri::DEFAULT_BASE_REMOTE_URI
		);
		$sut = $auth->getAdminUri();
		self::assertEquals(
			"/admin",
			$sut->getPath()
		);
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
			LoginUri::DEFAULT_BASE_REMOTE_URI,
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
			BaseResponseData::class,
			$newSessionData->getData()
		);
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
			LoginUri::DEFAULT_BASE_REMOTE_URI,
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
		$sut->getId();
	}

	public function testLogoutCallsLogoutUri() {
		$sessionData = self::createMock(SessionData::class);
		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData
		];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(function(UriInterface $uri):bool {
				if($uri->getHost() !== "login.authwave.com") {
					return false;
				}

				parse_str($uri->getQuery(), $queryParts);
				/** @var SessionData $session */
				$session = $_SESSION[Authenticator::SESSION_KEY];
				$token = $session->getToken();
				$decrypted = $token->decode(
					$queryParts[BaseProviderUri::QUERY_STRING_CIPHER]
				);
				var_dump($decrypted);die();
			}));

		$sut = new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
		$sut->logout();
		self::assertNotEmpty($_SESSION);
	}

	public function testCompleteAuthFromLogoutClearsSession() {
		$token = self::createMock(Token::class);

		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getToken")
			->willReturn($token);

		$_SESSION = [
			Authenticator::SESSION_KEY => $sessionData,
		];

		$responseCipher = "abcdef";

		$currentUri = "/example-page-" . uniqid();
		$currentUri .= "?";
		$currentUri .= http_build_query([
			Authenticator::RESPONSE_QUERY_PARAMETER => $responseCipher,
		]);

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getHost() == ""
				&& $uri->getPath() == $currentUri
			));

		new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);

		self::assertEmpty($_SESSION);
	}

	public function testLoginRedirects() {
		$_SESSION = [];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getHost() === LoginUri::DEFAULT_BASE_REMOTE_URI
			));

		$sut = new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
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
}
