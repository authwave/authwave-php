<?php
namespace Authwave;

use Gt\Session\SessionContainer;

class Authenticator {
	const SESSION_KEY = "AUTHWAVE_SESSION";

	private string $clientKey;
	private string $clientSecret;
	private string $redirectPath;
	private SessionContainer $session;
	private SessionData $sessionData;
	private RedirectHandler $redirectHandler;

	public function __construct(
		string $clientKey,
		string $clientSecret,
		string $redirectPath,
		SessionContainer $session = null,
		RedirectHandler $redirectHandler = null
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
		$this->session = $session;
		$this->sessionData = $session->get(self::SESSION_KEY);
		$this->redirectHandler = $redirectHandler ?? new RedirectHandler();

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

	public function login():void {
		if($this->isLoggedIn()) {
			return;
		}


	}

	public function logout():void {
// TODO: Should the logout redirect the user agent to the redirectPath?
		$this->session->remove(self::SESSION_KEY);
	}

	private function authInProgress():bool {
		return false;
	}

	private function completeAuth():void {

	}
}