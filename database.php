<?php
// config/database.php
// Returns $pdo as a global variable. Does not echo DB errors in production.

$host = getenv('DB_HOST') ?: '127.0.0.1';
$dbname = getenv('DB_NAME') ?: 'spoofshield';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';
$charset = 'utf8mb4';
$dsn = "mysql:host={$host};dbname={$dbname};charset={$charset}";

// Safe PDO options
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (PDOException $e) {
    // Log the error to server logs, do not echo sensitive details to clients
    error_log('DB connection error: ' . $e->getMessage());
    // If an API script includes this file, it may want to check $pdo
    $pdo = null;
}
