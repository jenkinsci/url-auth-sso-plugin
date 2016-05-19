<?php
// This script returns the current user's session data as JSON output.
// The user is 'authenticated' via session cookie (usually PHPSESSID).
// Cookies are not sent across domains by default so cross site request forgery is not an issue.
// Any other site requesting this page on behalf of a logged in user will receive 401 as no cookies will be sent.

session_start();
if(!isset($_SESSION["user_name"])) {http_response_code(401); exit;} // 401 Unauthorized - Authentication Failed

// 200 OK - Authentication successful

// Output: {"user_name":"", "display_name":"", "public_email":"", "profile_image":""}
// Remember that only "user_name" is required, the others are optional.
echo "{";
	echo '"user_name":"' . $_SESSION["user_name"] . '"';
	if(isset($_SESSION["display_name"]))	echo ', "display_name":"' . $_SESSION["display_name"] . '"';
	if(isset($_SESSION["public_email"]))	echo ', "public_email":"' . $_SESSION["public_email"] . '"';
	if(isset($_SESSION["profile_image"]))	echo ', "profile_image":"' . $_SESSION["profile_image"] . '"';
echo "}";

?>