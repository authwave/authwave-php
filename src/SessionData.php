<?php
namespace Authwave;

use Authwave\ResponseData\AbstractResponseData;
use Authwave\ResponseData\UserData;

class SessionData {
	private ?Token $token;
	private ?AbstractResponseData $data;

	public function __construct(
		Token $token = null,
		AbstractResponseData $data = null
	) {
		$this->token = $token;
		$this->data = $data;
	}

	public function getToken():Token {
		if(!isset($this->token)) {
			throw new NotLoggedInException();
		}

		return $this->token;
	}

	public function getData():AbstractResponseData {
		if(!isset($this->data)) {
			throw new NotLoggedInException();
		}

		return $this->data;
	}
}