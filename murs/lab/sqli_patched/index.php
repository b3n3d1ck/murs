<?php
// MURS LAB — PATCHED login. The secure comparison baseline.
?>
<!doctype html>
<title>MURS SQLi Lab (patched)</title>
<h1>Patched login</h1>
<form action="/login.php" method="post">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <input type="submit" value="Sign in">
</form>
