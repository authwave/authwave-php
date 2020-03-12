<?php
namespace Authwave;

use Gt\Http\Uri;

class AuthUri extends Uri {
	const DEFAULT_BASE_REMOTE_URI = "login.authwave.com";

	const QUERY_STRING_ID = "id";
	const QUERY_STRING_CIPHER = "cipher";
	const QUERY_STRING_INIT_VECTOR = "iv";
	const QUERY_STRING_CURRENT_PATH = "path";

	/**
	 * @param Token $token This must be the same instance of the Token when
	 * creating Authenticator for the first time as it is when checking the
	 * response from the Authwave provider (store in a session).
	 * @param string $clientId
	 * @param string $currentPath
	 * @param string $baseRemoteUri The base URI of the application. This is the
	 * URI authority with optional scheme, as localhost allows http://
	 */
	public function __construct(
		Token $token,
		string $clientId,
		string $currentPath = "/",
		string $baseRemoteUri = self::DEFAULT_BASE_REMOTE_URI
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);

		$this->query = http_build_query([
			self::QUERY_STRING_ID => $clientId,
			self::QUERY_STRING_CIPHER => (string)$token->generateRequestCipher(),
			self::QUERY_STRING_INIT_VECTOR => (string)$token->getIv(),
			self::QUERY_STRING_CURRENT_PATH => $currentPath,
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