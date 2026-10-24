<?php
// MURS LAB — intentionally VULNERABLE upload app. Localhost research only.
// Do not deploy. It accepts any file and stores it in a web-executable dir.
?>
<!doctype html>
<title>MURS Lab (vulnerable)</title>
<h1>Vulnerable upload</h1>
<form action="/upload.php" method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" value="Upload">
</form>
