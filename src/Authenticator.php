<?php
namespace Authwave;

use Gt\Http\Uri;
use Psr\Http\Message\UriInterface;

class Authenticator {
	private Token $token;
	private UriInterface $baseUri;
	private string $returnPath;

	/**
	 * @param Token $token This must be the same instance of the Token when
	 * creating Authenticator for the first time as it is when checking the
	 * response from the Authwave provider (store in a session).
	 * @param string $baseUri The base URI of the application. This is the
	 * URI authority with optional scheme, as localhost allows http://
	 */
	public function __construct(
		Token $token,
		string $baseUri,
		string $returnPath = "/"
	) {
		$this->token = $token;
		$this->baseUri = $this->normaliseBaseUri($baseUri);
		$this->returnPath = $returnPath;
	}

	/**
	 * The AuthUri is where to redirect the user agent to for authentication
	 * on the remote Authwave provider.
	 */
	public function getAuthUri():UriInterface {
		return new AuthUri(
			$this->baseUri,
			$this->token,
			$this->returnPath
		);
	}

	private function normaliseBaseUri(string $baseUri):Uri {
		$scheme = parse_url($baseUri, PHP_URL_SCHEME)
			?? "https";
		$host = parse_url($baseUri, PHP_URL_HOST)
			?? parse_url($baseUri, PHP_URL_PATH);

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