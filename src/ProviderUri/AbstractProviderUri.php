<?php
namespace Authwave\ProviderUri;

use Authwave\InsecureProtocolException;
use Gt\Http\Uri;

abstract class AbstractProviderUri extends Uri {
	const DEFAULT_BASE_REMOTE_URI = "login.authwave.com";

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
}