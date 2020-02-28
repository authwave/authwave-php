<?php
namespace Authwave;

class SessionData {
	private InitVector $iv;

	public function getIv():InitVector {
		if(!isset($this->iv)) {
			throw new InitVectorNotSetException();
		}

		return $this->iv;
	}

	public function setIv(InitVector $iv):void {
		$this->iv = $iv;
	}

	public function removeIv():void {
		unset($this->iv);
	}

	public function getUserData():UserData {
		if(!isset($this->userData)) {
			throw new UserDataNotSetException();
		}
	}
}