<?php
namespace Authwave;

use Gt\Session\SessionArrayWrapper;

class GlobalSessionContainer extends SessionArrayWrapper {
	const DEFAULT_SESSION_KEY = "AUTHWAVE_SESSION";

	public function __construct(
		string $baseSessionKey = self::DEFAULT_SESSION_KEY
	) {
		if(session_status() !== PHP_SESSION_ACTIVE) {
			session_start();
		}

		if(!isset($_SESSION[$baseSessionKey])) {
			$_SESSION[$baseSessionKey] = new SessionData();
		}

// TODO: Should this implement SessionContainer interface and define
// the getters and setters to $_SESSION itself, rather than being an
// instance of SessionArrayWrapper?

		parent::__construct($_SESSION[$baseSessionKey]);
	}
}