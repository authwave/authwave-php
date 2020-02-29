<?php
namespace Authwave;

class UserData {
	private string $uuid;
	private string $email;

	public function getUuid():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}
}