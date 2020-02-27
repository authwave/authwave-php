<?php
namespace Authwave;

use Gt\Session\SessionContainer;

class Authenticator {
	const SESSION_KEY_AUTH_FLOW = "authwave-authflow";
	const SESSION_KEY_USER_DATA = "authwave-userdata";

	public function __construct(
		string $clientKey,
		string $clientSecret,
		string $redirectPath,
		SessionContainer $session = null
	) {
		if(is_null($session)) {
			$session = new GlobalSessionContainer();
		}
	}
}