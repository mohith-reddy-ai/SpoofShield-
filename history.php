<?php
// api/history.php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/../config/database.php';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

$type = isset($_GET['type']) ? trim($_GET['type']) : null;
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = min(100, max(1, (int)($_GET['per_page'] ?? 25)));
$offset = ($page - 1) * $perPage;

$sql = 'SELECT id, investigation_id, target, type, scanned_at, risk_score, risk_level FROM scan_history';
$params = [];
if ($type) {
    $sql .= ' WHERE type = :type';
    $params[':type'] = $type;
}
$sql .= ' ORDER BY scanned_at DESC LIMIT :limit OFFSET :offset';

try {
    $stmt = $pdo->prepare($sql);
    // binds must be explicit for integer limit/offset on some PDO drivers
    if ($type) {
        $stmt->bindValue(':type', $type, PDO::PARAM_STR);
    }
    $stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'data' => ['items' => $items, 'page' => $page, 'per_page' => $perPage]]);
} catch (Exception $e) {
    error_log('history error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server error']);
}
