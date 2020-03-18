<?php
namespace Authwave\ProviderUri;

class LogoutUri extends AbstractProviderUri {
	const PATH_LOGOUT = "/logout";

	public function __construct(
		string $baseRemoteUri,
		string $returnToUri = "/"
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->path = self::PATH_LOGOUT;
		$this->query = http_build_query([
			"returnTo" => $returnToUri,
		]);
	}
}