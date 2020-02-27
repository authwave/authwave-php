<?php
namespace Authwave;

use Gt\Http\Uri;
use Psr\Http\Message\UriInterface;

class Authenticator {
	private Cipher $cipher;
	private UriInterface $baseUri;

	public function __construct(Token $token, string $baseUri) {
		$this->cipher = $token->generateCipher();
		$this->baseUri = $this->normaliseBaseUri($baseUri);
	}

	public function getAuthUri():UriInterface {
		return $this->baseUri;
	}

	private function normaliseBaseUri(string $baseUri):Uri {
		$scheme = parse_url($baseUri, PHP_URL_SCHEME) ?? "https";
		$host = parse_url($baseUri, PHP_URL_HOST) ??
			parse_url($baseUri, PHP_URL_PATH);

		$uri = (new Uri())
			->withScheme($scheme)
			->withHost($host);

		if($uri->getHost() !== "localhost"
		&& $uri->getScheme() !== "https") {
			throw new InsecureProtocolException($uri->getScheme());
		}

		return $uri;
	}
}