<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\GlobalSessionContainer;
use Authwave\SessionData;
use Authwave\SessionNotStartedException;
use Authwave\UserData;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase {
	public function testConstructWithDefaultSessionNotStarted() {
		self::expectException(SessionNotStartedException::class);
		new Authenticator(
			"test-key",
			"test-secret",
			"/"
		);
	}

	public function testConstructWithDefaultSession() {
		$_SESSION = [];
		new Authenticator(
			"test-key",
			"test-secret",
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
			"test-secret",
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
			"test-secret",
			"/"
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
			"/"
		);
		$sut->logout();
		self::assertEmpty($_SESSION);
	}
}