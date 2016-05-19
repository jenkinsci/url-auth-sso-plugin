<?php
// Authenticates a user with GitHub using OAuth.
// This script can be replaced with any system so long as it saves the correct session data once the user is logged in.

// REMEMBER to change the CLIENT ID, CLIENT SECRET and USER AGENT to your own values!
session_start();

// Register a new application at https://github.com/settings/developers
// The Authorization callback URL should point to this page.
$ghClientId = "CHANGE ME";     // CLIENT ID
$ghClientSecret = "CHANGE ME"; // CLIENT SECRET

// 2. Exchange auth code for token
if(isset($_GET['code'])) {
  if(!isset($_GET['state']) || $_SESSION['state'] != $_GET['state']) {
    // Invalid state, reject it
    header("Location: /");
    die();
  }

  $token = apiRequest("https://github.com/login/oauth/access_token", array(
    'client_id' => $ghClientId,
    'client_secret' => $ghClientSecret,
    'state' => $_SESSION['state'],
    'code' => $_GET['code']
  ));

  $_SESSION['access_token'] = $token->access_token;
  $user = apiRequest("https://api.github.com/user");
  
  // SESSION DATA
  // "user_name":     Used for raw login names, not display ones (prevents the security risk). User names must be unique.
  // "display_name":  Display Names aren't unique - they can be changed by the user to anything.
  // "public_email":  If the user has an email address, use it, or default to the raw username at GitHub noreply.
  // "profile_image": Holds the link to the user's profile image.
  $_SESSION['user_name'] = $user->login;
  $_SESSION['display_name'] = $user->name != null ? $user-> name : $user->login;
  $_SESSION['public_email'] = $user->email != null ? $user-> email : $user->login."@users.noreply.github.com";
  $_SESSION['profile_image'] = $user->avatar_url;

  // Redirect to the page the user has just come from
  header('Location: '.$_SESSION['return']);
  die();
}

// 1. Get request authorized by GitHub - REDIRECT TO GITHUB AUTH
$_SESSION['state'] = hash('sha256', microtime(TRUE).rand().$_SERVER['REMOTE_ADDR']);	// generate random hash for state
$_SESSION['return'] = isset($_SERVER["HTTP_REFERER"]) ? $_SERVER["HTTP_REFERER"] : "/";	// redirect to referring page; fall back on root page
unset($_SESSION['access_token']);

$params = array(
  'client_id' => $ghClientId,
  'scope' => 'user',
  'state' => $_SESSION['state']
);

header("Location: https://github.com/login/oauth/authorize?".http_build_query($params));
die();

// Makes a request to the GitHub API.
function apiRequest($url, $post=FALSE, $headers=array()) {
  // curl init
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

  // post data
  if($post) curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));

  // headers
  $headers[] = 'Accept: application/json';
  $headers[] = 'User-Agent: CHANGE ME'; // USER AGENT - include website URL (and purpose)
  if($_SESSION['access_token']) $headers[] = 'Authorization: Bearer ' . $_SESSION['access_token'];
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

  // response
  $response = curl_exec($ch);
  return json_decode($response);
}
?>
