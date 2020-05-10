<?php
namespace Authwave\ProviderUri;

class ProfileUri extends AbstractProviderUri {
	public function __construct(
		string $baseRemoteUri
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->path = "/profile";
	}
}