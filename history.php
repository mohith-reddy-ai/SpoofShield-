<?php
// api/history.php

require_once 'config/database.php';

function get_investigations($type = null, $limit = 50) {
    global $pdo;

    try {
        $sql = "SELECT * FROM scan_history";
        $params = [];

        if ($type) {
            $sql .= " WHERE type = :type";
            $params['type'] = $type;
        }

        $sql .= " ORDER BY timestamp DESC LIMIT :limit";
        $params['limit'] = (int)$limit;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log('Database error: ' . $e->getMessage());
        return [];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $type = isset($_GET['type']) ? $_GET['type'] : null;
    $limit = isset($_GET['limit']) ? $_GET['limit'] : 50;

    $limit = min((int)$limit, 100); // Limit to a sensible maximum

    $investigations = get_investigations($type, $limit);

    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'data' => [
            'items' => $investigations
        ]
    ]);
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method Not Allowed']);
}
?>