<?php
namespace Authwave;

use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\AdminUri;
use Authwave\ProviderUri\LoginUri;
use Authwave\ProviderUri\LogoutUri;
use Authwave\ProviderUri\ProfileUri;
use Authwave\ResponseData\UserResponseData;
use Gt\Cipher\Key;
use Gt\Cipher\Message\EncryptedMessage;
use Gt\Http\Uri;
use Gt\Session\SessionContainer;
use Psr\Http\Message\UriInterface;

class Authenticator {
	const RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA";

	private SessionData $sessionData;
	private User $user;
	private Uri $currentUri;

	public function __construct(
		private readonly string $clientKey,
		string|Uri $currentUri,
		private readonly string $authwaveHost = "login.authwave.com",
		private ?SessionContainer $session = null,
		private ?RedirectHandler $redirectHandler = null,
	) {
		$this->session = $this->session ?? new GlobalSessionContainer();
		$this->redirectHandler = $redirectHandler ?? new RedirectHandler();
		if($data = $this->session->get(SessionData::class)) {
			$this->sessionData = $data;

			try {
				$responseData = $this->sessionData->getData();
				if($responseData instanceof UserResponseData) {
					$this->user = new User(
						$responseData->getId(),
						$responseData->getEmail(),
						$responseData->getAllFields(),
					);
				}
			}
			catch(NotLoggedInException) {}
		}

		if(is_string($currentUri)) {
			$currentUri = new Uri($currentUri);
		}
		$this->currentUri = $currentUri;

		$this->completeAuth();
	}

	public function isLoggedIn():bool {
		return isset($this->user);
	}

	public function login(Token $token = null):void {
		if($this->isLoggedIn()) {
			return;
		}

		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		$this->sessionData = new SessionData($token);
		$this->session->set(SessionData::class, $this->sessionData);
		$this->redirectHandler->redirect($this->getLoginUri($token));
	}

	public function logout(Token $token = null):void {
		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		$this->sessionData = new SessionData($token);
		$this->session->set(SessionData::class, $this->sessionData);
		$this->redirectHandler->redirect($this->getLogoutUri($token));
	}

	public function getUser():User {
		if(!isset($this->user)) {
			throw new NotLoggedInException();
		}

		return $this->user;
	}

	public function getLoginUri(Token $token):BaseProviderUri {
		return new LoginUri(
			$token,
			$this->currentUri,
			$this->authwaveHost
		);
	}

	private function getLogoutUri(Token $token):BaseProviderUri {
		return new LogoutUri(
			$token,
			$this->currentUri,
			$this->authwaveHost
		);
	}

	public function getAdminUri():UriInterface {
		return new AdminUri($this->authwaveHost);
	}

	public function getProfileUri(Token $token = null):UriInterface {
		if(is_null($token)) {
			$token = new Token($this->clientKey);
		}

		return new ProfileUri(
			$token,
			$this->user->id,
			$this->currentUri,
			$this->authwaveHost
		);
	}

	private function completeAuth():void {
		$queryData = $this->getQueryData();

		if(!$queryData) {
			return;
		}

		if(!isset($this->sessionData)) {
			return;
		}

		$token = $this->sessionData->getToken();
		$secretSessionIv = $token->getSecretIv();
		$encrypted = new EncryptedMessage($queryData, $secretSessionIv);
		$key = new Key($this->clientKey);
		$decrypt = $encrypted->decrypt($key);
		parse_str($decrypt, $data);
		$userData = new UserResponseData(
			$data["id"],
			$data["email"],
			$data["kvp"] ?? [],
		);

		$this->session->set(
			SessionData::class,
			new SessionData($token, $userData)
		);

		$this->redirectHandler->redirect(
			(new Uri($this->currentUri))
			->withoutQueryValue(self::RESPONSE_QUERY_PARAMETER)
		);
	}

	private function getQueryData():?string {
		$queryString = parse_url(
			$this->currentUri,
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
