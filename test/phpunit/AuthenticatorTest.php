<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\GlobalSessionContainer;
use Authwave\SessionNotStartedException;
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
		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/"
		);
		self::assertArrayHasKey(
			GlobalSessionContainer::SESSION_KEY,
			$_SESSION
		);
	}
}