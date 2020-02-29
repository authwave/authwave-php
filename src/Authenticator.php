<?php
namespace Authwave;

use Gt\Session\SessionContainer;

class Authenticator {
	const SESSION_KEY = "AUTHWAVE_SESSION";

	private string $clientKey;
	private string $clientSecret;
	private string $currentUriPath;
	private string $authwaveHost;
	private SessionContainer $session;
	private SessionData $sessionData;
	private RedirectHandler $redirectHandler;

	public function __construct(
		string $clientKey,
		string $clientSecret,
		string $currentUriPath,
		string $authwaveHost = "login.authwave.com",
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
		$this->currentUriPath = $currentUriPath;
		$this->authwaveHost = $authwaveHost;
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
		catch(NotLoggedInException $exception) {
			return false;
		}

		return isset($userData);
	}

	public function login(Token $token = null):void {
		if($this->isLoggedIn()) {
			return;
		}

		if(is_null($token)) {
			$token = new Token($this->clientKey, $this->clientSecret);
		}

		$loginUri = new AuthUri(
			$token,
			$this->currentUriPath,
			$this->authwaveHost
		);
		$this->redirectHandler->redirect($loginUri);
	}

	public function logout():void {
// TODO: Should the logout redirect the user agent to the redirectPath?
		$this->session->remove(self::SESSION_KEY);
	}

	public function getUuid():string {
		$userData = $this->sessionData->getUserData();
		return $userData->getUuid();
	}

	private function authInProgress():bool {
		return false;
	}

	private function completeAuth():void {

	}
}