<?php
// api/health.php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, must-revalidate');
require_once __DIR__ . '/../config/database.php';

$response = [
    'success' => false,
    'status' => 'unknown',
];

try {
    if (isset($pdo) && $pdo instanceof PDO) {
        // quick lightweight query to validate DB
        $stmt = $pdo->prepare('SELECT 1');
        $stmt->execute();
        $response['success'] = true;
        $response['status'] = 'ok';
        http_response_code(200);
    } else {
        $response['status'] = 'database_unavailable';
        http_response_code(503);
    }
} catch (Exception $e) {
    error_log('health check error: ' . $e->getMessage());
    $response['status'] = 'error';
    http_response_code(500);
}

echo json_encode($response);
