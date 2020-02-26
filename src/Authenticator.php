<?php
namespace Authwave;

use Gt\Http\Uri;
use Psr\Http\Message\UriInterface;

class Authenticator {
	private Cipher $cipher;
	private string $httpsScheme = "https";
	private string $httpHost;

	public function __construct(Token $token, string $hostname) {
		$this->cipher = $token->generateCipher();
		$this->httpHost = $hostname;
	}

	public function useLocalhostHttps(bool $useHttps = true) {
		if(!$useHttps) {
			if($this->httpHost !== "localhost") {
				throw new InsecureProtocolException();
			}

			$this->httpsScheme = "http";
		}
	}

	public function getAuthUri():UriInterface {
		$uri = (new Uri())
			->withScheme("https")
			->withHost($this->httpHost);

		if($this->httpHost === "localhost") {
			$uri = $uri->withScheme($this->httpsScheme);
		}

		return $uri;
	}
}