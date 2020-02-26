<?php
namespace Authwave;

class Token {
	private string $key;
	private string $tokenValue;

	public function __construct(string $key) {
		$this->key = $key;
		$this->tokenValue = random_bytes(16);
	}

	public function generateCipher():Cipher {

	}
}