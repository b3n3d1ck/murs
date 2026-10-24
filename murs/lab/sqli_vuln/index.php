<?php
// MURS LAB — intentionally SQL-injectable login. Localhost research only.
?>
<!doctype html>
<title>MURS SQLi Lab (vulnerable)</title>
<h1>Vulnerable login</h1>
<form action="/login.php" method="post">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <input type="submit" value="Sign in">
</form>
