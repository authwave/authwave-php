<?php
namespace Authwave;

use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\AdminUriBase;
use Authwave\ProviderUri\LoginUriBase;
use Authwave\ProviderUri\LogoutUriBase;
use Authwave\ProviderUri\ProfileUriBase;
use Gt\Http\Uri;
use Gt\Session\SessionContainer;
use Psr\Http\Message\UriInterface;

class Authenticator {
	const SESSION_KEY = "AUTHWAVE_SESSION";
	const RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA";
	const LOGIN_TYPE_DEFAULT = "login-default";
	const LOGIN_TYPE_ADMIN = "login-admin";

	private SessionData $sessionData;

	public function __construct(
		private readonly string $clientKey,
		private readonly string $currentUriPath,
		private readonly string $authwaveHost = "login.authwave.com",
		private ?SessionContainer $session = null,
		private ?RedirectHandler $redirectHandler = null
	) {
		$this->session = $this->session ?? new GlobalSessionContainer();

		if(!$this->session->contains(self::SESSION_KEY)) {
// TODO: If there is no Token or UserData in the SessionData, do we even
// need to store it to the current session at all?
			$this->session->set(self::SESSION_KEY, new SessionData());
		}
		/** @var SessionData $sessionData*/
		$sessionData = $this->session->get(self::SESSION_KEY);

		$this->sessionData = $sessionData;
		$this->redirectHandler = $redirectHandler ?? new RedirectHandler();

		$this->completeAuth();
	}

	public function isLoggedIn():bool {
		try {
			$this->sessionData->getData();
		}
		catch(NotLoggedInException $exception) {
			return false;
		}

		return true;
	}

	public function login(Token $token = null):void {
		if($this->isLoggedIn()) {
			return;
		}

		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		$this->sessionData = new SessionData($token);
		$this->session->set(self::SESSION_KEY, $this->sessionData);

		$this->redirectHandler->redirect($this->getLoginUri($token));
	}

	public function logout(Token $token = null):void {
		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		$this->sessionData = new SessionData($token);
		$this->session->set(self::SESSION_KEY, $this->sessionData);

		$this->redirectHandler->redirect($this->getLogoutUri($token));
	}

	public function getId():string {
		$userData = $this->sessionData->getData();
		return $userData->getId();
	}

	public function getEmail():string {
		$userData = $this->sessionData->getData();
		return $userData->getEmail();
	}

	public function getField(string $name):?string {
		$userData = $this->sessionData->getData();
		return $userData->getField($name);
	}

	public function getLoginUri(Token $token):BaseProviderUri {
		return new LoginUriBase(
			$token,
			$this->currentUriPath,
			$this->authwaveHost
		);
	}

	private function getLogoutUri(Token $token):BaseProviderUri {
		return new LogoutUriBase(
			$token,
			$this->currentUriPath,
			$this->authwaveHost
		);
	}

	public function getAdminUri():UriInterface {
		return new AdminUriBase($this->authwaveHost);
	}

	public function getProfileUri(Token $token = null):UriInterface {
		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		return new ProfileUriBase(
			$token,
			$this->getId(),
			$this->currentUriPath,
			$this->authwaveHost
		);
	}

	private function completeAuth():void {
		return;
		$queryData = $this->getQueryData();

		if(!$queryData) {
			return;
		}

		$token = $this->sessionData->getToken();
		$userData = $token->decode($queryData);
		$this->session->set(
			self::SESSION_KEY,
			new SessionData($token, $userData)
		);

		$this->redirectHandler->redirect(
			(new Uri($this->currentUriPath))
			->withoutQueryValue(self::RESPONSE_QUERY_PARAMETER)
		);
	}

	private function getQueryData():?string {
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
