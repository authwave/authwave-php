<?php
namespace Authwave;

use Gt\Http\Uri;
use Psr\Http\Message\UriInterface;

class AuthUri extends Uri {
	const QUERY_STRING_CIPHER = "cipher";
	const QUERY_STRING_INIT_VECTOR = "iv";
	const QUERY_STRING_RETURN_PATH = "return";

	public function __construct(
		UriInterface $baseUri,
		Token $token,
		string $returnPath
	) {
		parent::__construct($baseUri);

		$this->query = http_build_query([
			self::QUERY_STRING_CIPHER => (string)$token->generateCipher(),
			self::QUERY_STRING_INIT_VECTOR => (string)$token->getIv(),
			self::QUERY_STRING_RETURN_PATH => base64_encode($returnPath),
		]);
	}
}