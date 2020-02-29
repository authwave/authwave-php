<?php
namespace Authwave;

class InitVector {
	private string $bytes;

	public function __construct(int $length = 16) {
		$this->bytes = random_bytes($length);
	}

	public function getBytes():string {
		return $this->bytes;
	}

	public function __toString():string {
		return bin2hex($this->bytes);
	}
}