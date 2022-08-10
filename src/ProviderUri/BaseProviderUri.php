<?php
namespace Authwave\ProviderUri;

use Authwave\InsecureProtocolException;
use Authwave\Token;
use Gt\Http\Uri;

abstract class BaseProviderUri extends Uri {
	const DEFAULT_BASE_REMOTE_URI = "login.authwave.com";
	const QUERY_STRING_CIPHER = "cipher";
	const QUERY_STRING_INIT_VECTOR = "iv";
	const QUERY_STRING_CURRENT_PATH = "path";

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
		&& $uri->getHost() !== "127.0.0.127"
		&& $uri->getScheme() !== "https") {
			throw new InsecureProtocolException($uri->getScheme());
		}

		return $uri;
	}

	protected function buildQuery(
		Token $token,
		string $currentPath,
		string $message = "",
	):string {
		return http_build_query([
			self::QUERY_STRING_CIPHER => (string)$token->generateRequestCipher($message),
			self::QUERY_STRING_INIT_VECTOR => (string)$token->getIv(),
			self::QUERY_STRING_CURRENT_PATH => bin2hex($currentPath),
		]);
	}
}
