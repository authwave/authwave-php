<?php
namespace Authwave;

class UserData {
	private string $uuid;
	private string $email;
	private object $fields;

	public function __construct(
		string $uuid,
		string $email,
		object $fields
	) {
		$this->uuid = $uuid;
		$this->email = $email;
		$this->fields = $fields;
	}

	public function getUuid():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}

	public function getField(string $name):?string {
		return $this->fields->{$name} ?? null;
	}
}