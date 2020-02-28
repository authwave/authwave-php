<?php
namespace Authwave;

use Gt\Session\SessionArrayWrapper;

class GlobalSessionContainer extends SessionArrayWrapper {
	public function __construct() {
		if(!isset($_SESSION)) {
			throw new SessionNotStartedException();
		}
		parent::__construct($_SESSION);
	}
}