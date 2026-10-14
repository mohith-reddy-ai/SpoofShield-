<?php
// api/report.php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

if (empty($_GET['id'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing id']);
    exit;
}

$idParam = $_GET['id'];
try {
    if (ctype_digit($idParam)) {
        $stmt = $pdo->prepare('SELECT * FROM scan_history WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => (int)$idParam]);
    } else {
        $stmt = $pdo->prepare('SELECT * FROM scan_history WHERE investigation_id = :iid LIMIT 1');
        $stmt->execute([':iid' => $idParam]);
    }
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Not found']);
        exit;
    }
    // Decode JSON fields safely
    $row['records'] = json_decode($row['records'] ?? 'null', true);
    $row['findings'] = json_decode($row['findings'] ?? 'null', true);
    $row['limitations'] = json_decode($row['limitations'] ?? 'null', true);
    echo json_encode(['success' => true, 'data' => $row]);
} catch (Exception $e) {
    error_log('report error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);
}
