<?php
namespace Authwave;

use Psr\Http\Message\UriInterface;

/** @codeCoverageIgnore */
class RedirectHandler {
	public function redirect(UriInterface $uri, int $code = 303):void {
		header("Location: $uri", true, $code);
		exit;
	}
}