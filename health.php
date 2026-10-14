<?php
// api/health.php

// Include the database connection configuration
require_once __DIR__ . '/../config/database.php';

// Prepare the response
$response = [
    'success' => false,
    'status' => 'Database connection failed',
];

// Check if the PDO connection is available
try {
    if ($pdo instanceof PDO) {
        $response['success'] = true;
        $response['status'] = 'Application is healthy';
    }
} catch (Exception $e) {
    // Handle any exceptions during the health check
    $response['status'] = 'Exception occurred: ' . $e->getMessage();
}

// Set no-cache headers
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Type: application/json');

// Return the JSON response
echo json_encode($response);