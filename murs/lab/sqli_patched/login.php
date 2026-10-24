<?php
// MURS LAB — PATCHED login handler. Prepared statements with bound parameters:
// a quote in the input is data, not syntax, so there is no error and no
// injection. This is the fix the assessment should recommend.
$dbfile = sys_get_temp_dir() . '/murs_sqli_patched.db';
$db = new SQLite3($dbfile);
$db->exec("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)");
$db->exec("DELETE FROM users");
$db->exec("INSERT INTO users (username, password) VALUES ('admin', 's3cr3t')");

$u = $_POST['username'] ?? $_GET['username'] ?? '';
$p = $_POST['password'] ?? $_GET['password'] ?? '';

$stmt = $db->prepare("SELECT username FROM users WHERE username = :u AND password = :p");
$stmt->bindValue(':u', $u, SQLITE3_TEXT);
$stmt->bindValue(':p', $p, SQLITE3_TEXT);
$res = $stmt->execute();
$row = $res->fetchArray(SQLITE3_ASSOC);
if ($row) {
    echo "WELCOME " . htmlspecialchars($row['username']);
} else {
    echo "Invalid credentials";
}
