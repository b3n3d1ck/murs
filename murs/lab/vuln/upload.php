<?php
// MURS LAB — VULNERABLE handler (deliberate). Localhost research only.
// Flaws, on purpose: no extension allowlist, no content check, original name
// kept, stored INSIDE the web root where the PHP built-in server will execute
// it on retrieval. This is how upload-to-RCE happens.
$dir = __DIR__ . '/uploads';
if (!is_dir($dir)) { mkdir($dir, 0777, true); }

if (empty($_FILES['file']['name'])) {
    http_response_code(400);
    echo "no file";
    return;
}
$name = basename($_FILES['file']['name']);
$dest = $dir . '/' . $name;
if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
    echo "stored at /uploads/" . $name;
} else {
    http_response_code(500);
    echo "store failed";
}
