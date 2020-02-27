<?php
namespace Authwave;

class InitVector {
	private string $bytes;

	public function __construct(int $length = 8) {
		$this->bytes = random_bytes($length);
	}

	public function __toString():string {
		return bin2hex($this->bytes);
	}
}