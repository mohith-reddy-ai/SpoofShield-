<?php
// api/report.php

require_once 'config/database.php';

function get_investigation($id) {
    global $pdo;

    try {
        $stmt = $pdo->prepare("SELECT * FROM scan_history WHERE id = :id");
        $stmt->execute(['id' => $id]);

        $investigation = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$investigation) {
            return null;
        }

        // Decode the findings summary safely
        $investigation['findings'] = json_decode($investigation['findings_summary'], true);

        return $investigation;
    } catch (PDOException $e) {
        error_log('Database error: ' . $e->getMessage());
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!isset($_GET['id']) || !filter_var($_GET['id'], FILTER_VALIDATE_INT) || $_GET['id'] <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid or missing ID']);
        exit;
    }

    $id = (int)$_GET['id'];

    $investigation = get_investigation($id);

    if (!$investigation) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Investigation not found']);
    } else {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'data' => [
                'target' => $investigation['target'],
                'type' => $investigation['type'],
                'risk_score' => $investigation['risk_score'],
                'risk_level' => $investigation['risk_level'],
                'timestamp' => $investigation['timestamp'],
                'findings' => $investigation['findings']
            ]
        ]);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method Not Allowed']);
}
?>