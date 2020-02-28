<?php
namespace Authwave;

use Gt\Http\Uri;

class AuthUri extends Uri {
	const DEFAULT_BASE_URI = "login.authwave.com";

	const QUERY_STRING_CIPHER = "cipher";
	const QUERY_STRING_INIT_VECTOR = "iv";
	const QUERY_STRING_RETURN_PATH = "return";

	/**
	 * @param Token $token This must be the same instance of the Token when
	 * creating Authenticator for the first time as it is when checking the
	 * response from the Authwave provider (store in a session).
	 * @param string $returnPath
	 * @param string $baseUri The base URI of the application. This is the
	 * URI authority with optional scheme, as localhost allows http://
	 */
	public function __construct(
		Token $token,
		string $returnPath = "/",
		string $baseUri = self::DEFAULT_BASE_URI
	) {
		$baseUri = $this->normaliseBaseUri($baseUri);

		parent::__construct($baseUri);

		$this->query = http_build_query([
			self::QUERY_STRING_CIPHER => (string)$token->generateCipher(),
			self::QUERY_STRING_INIT_VECTOR => (string)$token->getIv(),
			self::QUERY_STRING_RETURN_PATH => base64_encode($returnPath),
		]);
	}

	private function normaliseBaseUri(string $baseUri):Uri {
		$scheme = parse_url($baseUri, PHP_URL_SCHEME)
			?? "https";
		$host = parse_url($baseUri, PHP_URL_HOST)
			?? parse_url($baseUri, PHP_URL_PATH);
		$port = parse_url($baseUri, PHP_URL_PORT)
			?? 80;

		$uri = (new Uri())
			->withScheme($scheme)
			->withHost($host)
			->withPort($port);

		if($uri->getHost() !== "localhost"
		&& $uri->getScheme() !== "https") {
			throw new InsecureProtocolException($uri->getScheme());
		}

		return $uri;
	}
}