<?php
namespace Authwave;

use Authwave\ProviderUri\AbstractProviderUri;
use Authwave\ProviderUri\AdminUri;
use Authwave\ProviderUri\AuthUri;
use Authwave\ProviderUri\ProfileUri;
use Gt\Http\Uri;
use Gt\Session\SessionContainer;
use Psr\Http\Message\UriInterface;

class Authenticator {
	const SESSION_KEY = "AUTHWAVE_SESSION";
	const RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA";
	const LOGIN_TYPE_DEFAULT = "login-default";
	const LOGIN_TYPE_ADMIN = "login-admin";

	private string $clientKey;
	private string $currentUriPath;
	private string $authwaveHost;
	private SessionContainer $session;
	private SessionData $sessionData;
	private RedirectHandler $redirectHandler;

	public function __construct(
		string $clientKey,
		string $currentUriPath,
		string $authwaveHost = "login.authwave.com",
		SessionContainer $session = null,
		RedirectHandler $redirectHandler = null
	) {
		if(is_null($session)) {
			$session = new GlobalSessionContainer();
		}

		if(!$session->contains(self::SESSION_KEY)) {
// TODO: If there is no Token or UserData in the SessionData, do we even
// need to store it to the current session at all?
			$session->set(self::SESSION_KEY, new SessionData());
		}

		$this->clientKey = $clientKey;
		$this->currentUriPath = $currentUriPath;
		$this->authwaveHost = $authwaveHost;
		$this->session = $session;
		$this->sessionData = $session->get(self::SESSION_KEY);
		$this->redirectHandler = $redirectHandler ?? new RedirectHandler();

		$this->completeAuth();
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

	public function login(
		Token $token = null,
		string $loginType = self::LOGIN_TYPE_DEFAULT
	):void {
		if($this->isLoggedIn()) {
			return;
		}

		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		$this->sessionData = new SessionData($token);
		$this->session->set(self::SESSION_KEY, $this->sessionData);

		$this->redirectHandler->redirect(
			$this->getAuthUri($token, $loginType)
		);
	}

	public function logout():void {
// TODO: Should the logout redirect the user agent to the redirectPath?
		$this->session->remove(self::SESSION_KEY);
	}

	public function adminLogin(Token $token = null):void {
		$this->login($token, self::LOGIN_TYPE_ADMIN);
	}

	public function getUuid():string {
		$userData = $this->sessionData->getUserData();
		return $userData->getUuid();
	}

	public function getEmail():string {
		$userData = $this->sessionData->getUserData();
		return $userData->getEmail();
	}

	public function getField(string $name):?string {
		$userData = $this->sessionData->getUserData();
		return $userData->getField($name);
	}

	public function getAuthUri(
		Token $token,
		string $loginType = self::LOGIN_TYPE_DEFAULT
	):AbstractProviderUri {
		if($loginType === self::LOGIN_TYPE_ADMIN) {
			return new AdminUri(
				$this->currentUriPath,
				$this->authwaveHost
			);
		}

		return new AuthUri(
			$token,
			$this->currentUriPath,
			$this->authwaveHost
		);
	}

	public function getAdminUri():UriInterface {
		return new AdminUri($this->authwaveHost);
	}

	public function getProfileUri():UriInterface {
		return new ProfileUri($this->authwaveHost);
	}

	private function completeAuth():void {
		$responseCipher = $this->getResponseCipher();

		if(!$responseCipher) {
			return;
		}

		$token = $this->sessionData->getToken();
		$userData = $token->decryptResponseCipher($responseCipher);
		$this->session->set(
			self::SESSION_KEY,
			new SessionData($token, $userData)
		);

		$this->redirectHandler->redirect(
			(new Uri($this->currentUriPath))
			->withoutQueryValue(self::RESPONSE_QUERY_PARAMETER)
		);
	}

	private function getResponseCipher():?string {
		$queryString = parse_url(
			$this->currentUriPath,
			PHP_URL_QUERY
		);
		if(!$queryString) {
			return null;
		}

		$queryParts = [];
		parse_str($queryString, $queryParts);
		if(empty($queryParts[self::RESPONSE_QUERY_PARAMETER])) {
			return null;
		}

		return $queryParts[self::RESPONSE_QUERY_PARAMETER];
	}
}