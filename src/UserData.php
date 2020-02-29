<?php
namespace Authwave;

class UserData {
	private string $uuid;
	private string $email;

	public function __construct(string $uuid, string $email) {
		$this->uuid = $uuid;
		$this->email = $email;
	}

	public function getUuid():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}
}