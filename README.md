PHP client library to implement Authwave in your application
============================================================

Authwave is an open source Identity-as-a-Service product that can be self-hosted. Using Authwave allows your application to offer authentication with great user experience and security, without you having to program any of the authentication yourself.

To use this repository, your application must be registered to obtain a client key (see example below). This can be done from https://www.authwave.com or from your own instance of [Authwave Provider](https://github.com/Authwave/provider) if you are self-hosting.

Basic usage
-----------

With the following PHP code below, you can display a log in button that, when clicked, changes to a log out button and displays a greeting to the logged in user.

```php
<?php
use Authwave\Authenticator;
require __DIR__ . "/vendor/autoload.php";

// This constant can be loaded from your application's configuration
// or environment variables. It is created in the remote Authwave provider.
define("CLIENT_KEY", "1234567890abcdef");

// Construct the Authenticator class as soon as possible, as this handles the
// Authentication steps passed via the query string from the remote provider.
$auth = new Authenticator(
	CLIENT_KEY,
	$_SERVER["REQUEST_URI"]
);

// Handle authentication login/logout action via the querystring:
if(isset($_GET["login"])) {
// This will redirect the user agent to the auth uri, which is a location on the 
// remote provider. The remote provider will in turn redirect the user agent
// back to the return URI (set as 3rd parameter of Authenticator's constructor),
// at which point the user will be considered authenticated.
	$auth->login();
}
elseif(isset($_GET["logout"])) {
	$auth->logout();
}

// Authentication is handled by Authwave, so you can trust "isLoggedIn"
// as a mechanism for protecting your sensitive information.
if($auth->isLoggedIn()) {
	echo <<<HTML
		<p>You are logged in as <strong>{$auth->getEmail()}</strong></p>
		<p><a href="?logout">Log out</a></p>
	HTML;
}
else {
	echo <<<HTML
		<p>You are not logged in!</p>
		<p><a href="?login">Log in</a></p>
	HTML;
}
```