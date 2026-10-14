<?php

// api/email_analyze.php

require_once 'config/database.php';

header('Content-Type: application/json');

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
    exit;
}

// Safely parse JSON input
$input = file_get_contents('php://input');
if (empty($input) || strlen($input) > 65536) {
    echo json_encode(['success' => false, 'error' => 'Invalid input']);
    exit;
}

$request = json_decode($input, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    echo json_encode(['success' => false, 'error' => 'Invalid JSON']);
    exit;
}

if (!isset($request['headers']) || empty($request['headers'])) {
    echo json_encode(['success' => false, 'error' => 'Headers are required']);
    exit;
}

// Extract email headers
$headers = $request['headers'];
$headerLines = explode("\n", $headers);
$parsedHeaders = [];
$spfResult = null;
$dmarcResult = null;
$dkimResult = null;
$findings = [];
$authentication = [];
$limitations = [];

foreach ($headerLines as $line) {
    list($key, $value) = explode(': ', $line, 2);
    if (!isset($key) || !isset($value)) {
        continue;
    }

    $parsedHeaders[$key] = $value;

    switch (trim($key)) {
        case 'Received-SPF':
            $spfResult = $value;
            break;
        case 'Authentication-Results':
            $authenticationResults = $value;
            $authParts = explode('; ', $authenticationResults);
            foreach ($authParts as $authPart) {
                if (strpos($authPart, 'spf=') === 0) {
                    $spfResult = $authPart;
                } elseif (strpos($authPart, 'dkim=') === 0) {
                    $dkimResult = $authPart;
                } elseif (strpos($authPart, 'dmarc=') === 0) {
                    $dmarcResult = $authPart;
                }
            }
            break;
        case 'DKIM-Signature':
            $dkimResult = $value;
            break;
    }
}

// Check SPF and DMARC results
if ($spfResult) {
    if (strpos($spfResult, 'fail') !== false) {
        $findings[] = ['SPF failure' => $spfResult];
    } elseif (strpos($spfResult, 'pass') === false) {
        $findings[] = ['SPF inconclusive or neutral' => $spfResult];
    }
}

if ($dmarcResult) {
    if (strpos($dmarcResult, 'fail') !== false) {
        $findings[] = ['DMARC failure' => $dmarcResult];
    } elseif (strpos($dmarcResult, 'pass') === false) {
        $findings[] = ['DMARC inconclusive or neutral' => $dmarcResult];
    }
}

// Suggest limitations
if (!array_key_exists('From', $parsedHeaders) || !array_key_exists('Return-Path', $parsedHeaders)) {
    $limitations[] = 'From or Return-Path headers are missing.';
} elseif (trim($parsedHeaders['From']) !== trim($parsedHeaders['Return-Path'])) {
    $findings[] = ['Mismatch between From and Return-Path' => $parsedHeaders['From'] . ' vs ' . $parsedHeaders['Return-Path']];
}

// Calculate heuristic risk score
$riskScore = 0;
if (count($findings) > 0) {
    foreach ($findings as $finding) {
        $riskScore += 30;
    }
}

$riskLevel = $riskScore > 75 ? 'High' : ($riskScore > 30 ? 'Medium' : 'Low');

// Store summary in scan_history
try {
    $db = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME, DB_USER, DB_PASSWORD);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $db->prepare('INSERT INTO scan_history (target, analyzed_at, risk_score, risk_level, findings, authentication, limitations) VALUES (:target, :analyzed_at, :risk_score, :risk_level, :findings, :authentication, :limitations)');
    $stmt->execute([
        ':target' => isset($parsedHeaders['From']) ? $parsedHeaders['From'] : 'Unknown',
        ':analyzed_at' => date('c'),
        ':risk_score' => $riskScore,
        ':risk_level' => $riskLevel,
        ':findings' => json_encode($findings),
        ':authentication' => json_encode($authentication),
        ':limitations' => json_encode($limitations),
    ]);
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'error' => 'Failed to save scan history']);
    exit;
}

// Return result
echo json_encode([
    'success' => true,
    'data' => [
        'id' => $db->lastInsertId(),
        'target' => isset($parsedHeaders['From']) ? $parsedHeaders['From'] : 'Unknown',
        'analyzed_at' => date('c'),
        'risk_score' => $riskScore,
        'risk_level' => $riskLevel,
        'findings' => $findings,
        'authentication' => $authentication,
        'limitations' => $limitations,
    ],
]);

?>