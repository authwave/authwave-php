<?php
namespace Authwave\ResponseData;

class UserData extends AbstractResponseData {
	private string $uuid;
	private string $email;
	private object $fields;

	public function __construct(
		string $uuid,
		string $email,
		object $fields,
		string $message = null
	) {
		$this->uuid = $uuid;
		$this->email = $email;
		$this->fields = $fields;

		parent::__construct($message);
	}

	public function getId():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}

	public function getField(string $name):?string {
		return $this->fields->{$name} ?? null;
	}
}
