<?php
namespace Authwave;

use Authwave\ResponseData\AbstractResponseData;
use Authwave\ResponseData\UserData;
use Gt\Cipher\CipherText;
use Gt\Cipher\InitVector;
use Gt\Cipher\Key;
use Gt\Cipher\Message\EncryptedMessage;
use Gt\Cipher\Message\PlainTextMessage;
use StdClass;

class Token {
	private Key $key;
	private InitVector $secretIv;
	private InitVector $iv;

	public function __construct(
		string $keyString,
		InitVector $sessionIv = null,
		InitVector $iv = null,
	) {
		$this->key = new Key($keyString);
		$this->secretIv = $sessionIv ?? new InitVector();
		$this->iv = $iv ?? new InitVector();
	}

	public function getIv():InitVector {
		return $this->iv;
	}

/**
 * The request cipher is sent to the remote provider in the querystring. It
 * consists of the token's secret IV, encrypted with the client key, along with
 * an optional message. The secret IV is required for two-way encryption. The
 * remote provider will decrypt the secret and use it as the key if encrypting a
 * response cipher, which will be sent back to the client application in the
 * querystring.
 */
	public function generateRequestCipher(string $message = ""):CipherText {
		$plainTextMessage = new PlainTextMessage($message, $this->getIv());
		return $plainTextMessage->encrypt($this->key);
	}

// The response cipher is send from the remote provider back to the client
// application after a successful authentication and includes a serialised
// UserData object, encrypted using the secret IV, which was created when
// encrypting the original request cipher.
	public function decode(string $base64cipher):AbstractResponseData {
		$encryptedMessage = new EncryptedMessage(
			$base64cipher,
			$this->iv,
		);
		$decrypted = $encryptedMessage->decrypt($this->key);

		if(!$decrypted) {
			throw new ResponseCipherDecryptionException();
		}

		$data = @unserialize(
			$decrypted
		);
		if($data === false) {
			throw new InvalidUserDataSerializationException();
		}

		return new UserData(
			$data->{"uuid"},
			$data->{"email"},
			$data->{"fields"} ?? new StdClass()
		);
	}
}
