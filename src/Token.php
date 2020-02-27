<?php
namespace Authwave;

class Token {
	const ENCRYPTION_METHOD = "aes128";

	private string $key;
	private string $secret;
	private InitVector $iv;

	public function __construct(
		string $key,
		string $secret,
		InitVector $iv = null
	) {
		$this->key = $key;
		$this->secret = $secret;
		$this->iv = $iv ?? new InitVector();
	}

	public function generateCipher():string {
		$rawCipher = openssl_encrypt(
			$this->secret,
			self::ENCRYPTION_METHOD,
			$this->key,
			0,
			$this->iv
		);

		return base64_encode($rawCipher);
	}

	public function getIv():InitVector {
		return $this->iv;
	}
}