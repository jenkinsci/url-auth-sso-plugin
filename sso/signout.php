<?
// Signs the user out completely by deleting all data from the current session.
session_start();
$_SESSION = array();

// Send the user back to the page they were on; fall back on the domain's root page.
header("Location: ".(isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : "/"));
?>