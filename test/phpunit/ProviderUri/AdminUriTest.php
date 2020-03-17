<?php
namespace Authwave\Test\ProviderUri;

use Authwave\ProviderUri\AdminUri;
use PHPUnit\Framework\TestCase;

class AdminUriTest extends TestCase {
	public function testPathAccount() {
		$sut = new AdminUri(
			"example.com",
			AdminUri::PATH_ACCOUNT
		);
		self::assertEquals(
			AdminUri::PATH_ACCOUNT,
			$sut->getPath()
		);
	}

	public function testPathSettings() {
		$sut = new AdminUri(
			"example.com",
			AdminUri::PATH_SETTINGS
		);
		self::assertEquals(
			AdminUri::PATH_SETTINGS,
			$sut->getPath()
		);
	}

	public function testPathCustom() {
		$path = "/custom/path";
		$sut = new AdminUri(
			"example.com",
			$path
		);
		self::assertEquals($path, $sut->getPath());
	}
}