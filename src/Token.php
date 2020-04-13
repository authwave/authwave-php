<?php
namespace Authwave;

class Token {
	const ENCRYPTION_METHOD = "aes128";

	private string $key;
	private InitVector $secretIv;
	private InitVector $iv;

	public function __construct(
		string $key,
		InitVector $secretIv = null,
		InitVector $iv = null
	) {
		$this->key = $key;
		$this->secretIv = $secretIv ?? new InitVector();
		$this->iv = $iv ?? new InitVector();
	}

	public function getIv():InitVector {
		return $this->iv;
	}

// The request cipher is sent to the remote provider in the querystring. It
// consists of the secret IV, encrypted with the client key. The remote provider
// will decrypt the secret and use it as the key when encrypting the response
// cipher, which will be sent back to the client application in the querystring.
	public function generateRequestCipher():string {
		$rawCipher = openssl_encrypt(
			$this->secretIv,
			self::ENCRYPTION_METHOD,
			$this->key,
			0,
			$this->iv->getBytes()
		);

		return base64_encode($rawCipher);
	}

// The response cipher is send from the remote provider back to the client
// application after a successful authentication and includes a serialised
// UserData object, encrypted using the secret IV, which was created when
// encrypting the original request cipher.
	public function decryptResponseCipher(string $cipher):UserData {
		$decrypted = openssl_decrypt(
			base64_decode($cipher),
			self::ENCRYPTION_METHOD,
			$this->key,
			0,
			$this->secretIv->getBytes()
		);

		if(!$decrypted) {
			throw new ResponseCipherDecryptionException();
		}

		$data = @unserialize(
			$decrypted
		);
		if($data === false) {
			throw new InvalidUserDataSerializationException();
		}

		return new UserData($data->{"uuid"}, $data->{"email"});
	}
}