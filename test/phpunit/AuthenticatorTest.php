<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase {
	public function testConstructWithDefaultSession() {
		$sut = new Authenticator(
			"test-key",
			"test-secret",
			"/"
		);
	}
}