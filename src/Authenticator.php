<?php
namespace Authwave;

use Gt\Session\SessionContainer;

class Authenticator {
	const SESSION_KEY = "AUTHWAVE_SESSION";

	private string $clientKey;
	private string $clientSecret;
	private string $redirectPath;
	private SessionData $sessionData;

	public function __construct(
		string $clientKey,
		string $clientSecret,
		string $redirectPath,
		SessionContainer $session = null
	) {
		if(is_null($session)) {
			$session = new GlobalSessionContainer();
		}

		if(!$session->contains(self::SESSION_KEY)) {
			$session->set(self::SESSION_KEY, new SessionData());
		}

		$this->clientKey = $clientKey;
		$this->clientSecret = $clientSecret;
		$this->redirectPath = $redirectPath;
		$this->sessionData = $session->get(self::SESSION_KEY);

		if($this->authInProgress()) {
			$this->completeAuth();
		}
	}

	public function isLoggedIn():bool {
		$userData = null;

		try {
			$userData = $this->sessionData->getUserData();
		}
		catch(UserDataNotSetException $exception) {
			return false;
		}

		return isset($userData);
	}

	private function authInProgress():bool {
		return false;
	}

	private function beginAuth():void {

	}

	private function completeAuth():void {

	}
}