<?php
namespace Authwave;

class SessionData {
	private ?Token $token;
	private ?UserData $userData;

	public function __construct(
		Token $token = null,
		UserData $userData = null
	) {
		$this->token = $token;
		$this->userData = $userData;
	}

	public function getToken():Token {
		if(!isset($this->token)) {
			throw new NotLoggedInException();
		}

		return $this->token;
	}

	public function getUserData():UserData {
		if(!isset($this->userData)) {
			throw new NotLoggedInException();
		}

		return $this->userData;
	}
}