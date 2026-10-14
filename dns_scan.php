<?php
// api/dns_scan.php

// Include PDO configuration
$dbHost = 'localhost';
$dbName = 'spoofshield';
$dbUser = 'root';
$dbPass = '';

try {
    $pdo = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Database connection failed']);
    exit;
}

// Validate and sanitize input
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Malformed JSON']);
    exit;
}

$domain = trim((string)$input['domain']);
if (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid domain']);
    exit;
}

// Fetch DNS records
$records = [
    'A' => dns_get_record($domain, DNS_A),
    'AAAA' => dns_get_record($domain, DNS_AAAA),
    'MX' => dns_get_record($domain, DNS_MX),
    'NS' => dns_get_record($domain, DNS_NS),
    'TXT' => dns_get_record($domain, DNS_TXT),
];

$spf = '';
$dmarc = '';
foreach ($records['TXT'] as $record) {
    if (strpos($record['txt'], 'v=spf1') === 0) {
        $spf = $record['txt'];
    }
    if ($record['hostname'] === '_dmarc.' . $domain) {
        $dmarc = $record['txt'];
    }
}

// Calculate risk score and level
$riskScore = 0;
$findings = [];
$limitations = [];

if (empty($spf)) {
    $findings[] = 'No SPF record found.';
} else if (strpos($spf, '+all') !== false) {
    $findings[] = 'SPF record is permissive (\'+all\').';
    $riskScore += 30;
}

if (empty($dmarc)) {
    $findings[] = 'No DMARC record found.';
} else if (strpos($dmarc, 'p=none') === false && strpos($dmarc, 'p=quarantine') === false && strpos($dmarc, 'p=reject') === false) {
    $findings[] = 'DMARC policy not set to \'none\', \'quarantine\', or \'reject\'.';
    $riskScore += 40;
}

$riskLevels = ['Low', 'Moderate', 'High'];
$riskLevel = $riskLevels[min(2, floor($riskScore / 50))];

// Store scan history
$scannedAt = date('Y-m-d H:i:s');
$investigationId = uniqid();

$stmt = $pdo->prepare('INSERT INTO scan_history (investigation_id, domain, scanned_at, records, risk_score, risk_level, findings, limitations) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
$stmt->execute([$investigationId, $domain, $scannedAt, json_encode($records), $riskScore, $riskLevel, json_encode($findings), json_encode($limitations)]);

// Return results
http_response_code(200);
echo json_encode([
    'success' => true,
    'data' => [
        'domain' => $domain,
        'scanned_at' => $scannedAt,
        'records' => $records,
        'risk_score' => $riskScore,
        'risk_level' => $riskLevel,
        'findings' => $findings,
        'limitations' => $limitations,
        'investigation_id' => $investigationId,
    ],
]);
?>