<?php
namespace Authwave\ProviderUri;

use Authwave\InsecureProtocolException;
use Authwave\Token;
use Gt\Http\Uri;

abstract class AbstractProviderUri extends Uri {
	const DEFAULT_BASE_REMOTE_URI = "login.authwave.com";
	const QUERY_STRING_CIPHER = "c";
	const QUERY_STRING_INIT_VECTOR = "i";
	const QUERY_STRING_CURRENT_PATH = "p";

	protected function normaliseBaseUri(string $baseUri):Uri {
		$scheme = parse_url($baseUri, PHP_URL_SCHEME)
			?? "https";
		$host = parse_url($baseUri, PHP_URL_HOST)
			?? parse_url($baseUri, PHP_URL_PATH);
		$port = parse_url($baseUri, PHP_URL_PORT)
			?? null;

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

	protected function buildQuery(
		Token $token,
		string $currentPath,
		string $data = null
	):string {
		return http_build_query([
			self::QUERY_STRING_CIPHER => (string)$token->generateRequestCipher($data),
			self::QUERY_STRING_INIT_VECTOR => (string)$token->getIv(),
			self::QUERY_STRING_CURRENT_PATH => bin2hex($currentPath),
		]);
	}
}