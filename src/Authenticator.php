<?php
namespace Authwave;

use Gt\Http\Uri;
use Psr\Http\Message\UriInterface;

class Authenticator {
	private Cipher $cipher;
	private string $hostname;

	public function __construct(Token $token, string $hostname) {
		$this->cipher = $token->generateCipher();
		$this->hostname = $hostname;
	}

	public function getAuthUri():UriInterface {
		return (new Uri())
			->withScheme("https")
			->withHost($this->hostname);
	}
}