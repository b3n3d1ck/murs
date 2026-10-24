<?php
// MURS LAB — VULNERABLE login handler (deliberate). Localhost research only.
// Flaw on purpose: user input is interpolated straight into the SQL string, so
// a quote breaks the query and the SQLite error is surfaced (error-based SQLi).
$dbfile = sys_get_temp_dir() . '/murs_sqli_vuln.db';
$db = new SQLite3($dbfile);
$db->exec("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)");
$db->exec("DELETE FROM users");
$db->exec("INSERT INTO users (username, password) VALUES ('admin', 's3cr3t')");

$u = $_POST['username'] ?? $_GET['username'] ?? '';
$p = $_POST['password'] ?? $_GET['password'] ?? '';

$query = "SELECT username FROM users WHERE username='$u' AND password='$p'";
$res = @$db->query($query);
if ($res === false) {
    http_response_code(500);
    echo "SQL error: " . $db->lastErrorMsg();  // leaks the DB error on purpose
    exit;
}
$row = $res->fetchArray(SQLITE3_ASSOC);
if ($row) {
    echo "WELCOME " . htmlspecialchars($row['username']);
} else {
    echo "Invalid credentials";
}
