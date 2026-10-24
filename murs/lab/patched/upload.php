<?php
// MURS LAB — PATCHED handler. Demonstrates the fixes:
//   * extension allowlist (no php/phtml/etc.)
//   * content check: reject anything containing a PHP open tag
//   * randomised name
//   * stored OUTSIDE the web root (not retrievable, never executed)
$allowed = ['png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'];
$store = __DIR__ . '/../storage_patched';
if (!is_dir($store)) { mkdir($store, 0777, true); }

if (empty($_FILES['file']['name'])) {
    http_response_code(400);
    echo "no file";
    return;
}
$orig = basename($_FILES['file']['name']);
$ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
$data = file_get_contents($_FILES['file']['tmp_name']);

if (!in_array($ext, $allowed, true) || strpos($data, '<?php') !== false) {
    http_response_code(422);
    echo "rejected: file type not allowed by policy";
    return;
}
$rand = bin2hex(random_bytes(8)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $store . '/' . $rand);
echo "stored safely outside the web root as " . $rand;
