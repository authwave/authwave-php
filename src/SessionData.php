<?php
namespace Authwave;

class SessionData {
	private InitVector $iv;

	// TODO: Store User data here too.

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
}