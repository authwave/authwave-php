<?php
namespace Authwave\Test\ProviderUri;

use Authwave\ProviderUri\AdminUriBase;
use PHPUnit\Framework\TestCase;

class AdminUriTest extends TestCase {
	public function testPathAccount() {
		$sut = new AdminUriBase("example.com");
		self::assertEquals(
			"/admin",
			$sut->getPath()
		);
	}
}
