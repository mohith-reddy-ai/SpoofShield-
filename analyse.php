<?php
// api/email_analyze.php
header('Content-Type: application/json; charset=utf-8');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

$maxBody = 64 * 1024; // 64KB
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > $maxBody) {
    http_response_code(413);
    echo json_encode(['success' => false, 'message' => 'Request too large or empty']);
    exit;
}
$input = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Malformed JSON']);
    exit;
}
$headersRaw = isset($input['headers']) ? (string)$input['headers'] : (isset($input['raw']) ? (string)$input['raw'] : '');
if (empty($headersRaw)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Email headers required']);
    exit;
}

require_once __DIR__ . '/../config/database.php';

// Basic parsing: split into lines, trim
$lines = preg_split("/\r\n|\n|\r/", $headersRaw);
$parsed = [];
$current = '';
foreach ($lines as $line) {
    if (preg_match('/^\s+/', $line)) {
        // continuation line
        $current .= ' ' . trim($line);
    } else {
        if ($current !== '') {
            // store previous
            $parts = explode(':', $current, 2);
            if (count($parts) === 2) {
                $name = strtolower(trim($parts[0]));
                $value = trim($parts[1]);
                $parsed[$name][] = $value;
            }
        }
        $current = $line;
    }
}
// last line
if ($current !== '') {
    $parts = explode(':', $current, 2);
    if (count($parts) === 2) {
        $name = strtolower(trim($parts[0]));
        $value = trim($parts[1]);
        $parsed[$name][] = $value;
    }
}

// Heuristics
$findings = [];
$limitations = [];
$riskScore = 0;

// Check for Authentication-Results header
if (empty($parsed['authentication-results'])) {
    $limitations[] = 'No Authentication-Results header; cannot fully assess SPF/DKIM/DMARC results from headers.';
    $riskScore += 20;
} else {
    // inspect auth results minimally
    foreach ($parsed['authentication-results'] as $ar) {
        if (stripos($ar, 'spf=pass') !== false) {
            // good for SPF
        } elseif (stripos($ar, 'spf=fail') !== false || stripos($ar, 'spf=softfail') !== false) {
            $findings[] = 'SPF result indicates failure/softfail in Authentication-Results header.';
            $riskScore += 30;
        }
        if (stripos($ar, 'dkim=pass') !== false) {
            // DKIM pass noted; we DO NOT claim cryptographic verification beyond header claim.
        } elseif (stripos($ar, 'dkim=fail') !== false) {
            $findings[] = 'DKIM reported as fail in Authentication-Results.';
            $riskScore += 30;
        }
        if (stripos($ar, 'dmarc=pass') !== false) {
            // ok
        } elseif (stripos($ar, 'dmarc=fail') !== false) {
            $findings[] = 'DMARC reported as fail in Authentication-Results.';
            $riskScore += 20;
        }
    }
}

// Received headers analysis - look for suspicious originating IPs or obfuscated hops
if (!empty($parsed['received'])) {
    $received = $parsed['received'];
    // penalize if many hops from uncommon networks or missing trusted MX hops
    if (count($received) > 4) {
        $limitations[] = 'Many Received hops (>4) observed; chain may include relays.';
        $riskScore += 5;
    }
    // simple check: presence of "by" vs "from" anomalies
    foreach ($received as $r) {
        if (preg_match('/\bhelo=spam\b/i', $r)) {
            $findings[] = 'Suspicious received header content detected.';
            $riskScore += 20;
        }
    }
} else {
    $limitations[] = 'No Received headers found.';
    $riskScore += 10;
}

// Check for Return-Path vs From mismatch
$from = isset($parsed['from'][0]) ? $parsed['from'][0] : null;
$returnPath = isset($parsed['return-path'][0]) ? $parsed['return-path'][0] : null;
if ($from && $returnPath) {
    // attempt to extract domains
    preg_match('/@([A-Za-z0-9\.\-]+)/', $from, $mFrom);
    preg_match('/@([A-Za-z0-9\.\-]+)/', $returnPath, $mRet);
    $domainFrom = $mFrom[1] ?? null;
    $domainRet = $mRet[1] ?? null;
    if ($domainFrom && $domainRet && strcasecmp($domainFrom, $domainRet) !== 0) {
        $findings[] = 'From address domain and Return-Path domain differ.';
        $riskScore += 15;
    }
}

// other checks: presence of DKIM-Signature header is good signal (but we do not cryptographically verify here)
if (!empty($parsed['dkim-signature'])) {
    // slight reduction of risk if present
    $riskScore = max(0, $riskScore - 5);
}

// clamp
$riskScore = max(0, min(100, (int)$riskScore));
$riskLevel = $riskScore >= 60 ? 'High' : ($riskScore >= 30 ? 'Moderate' : 'Low');

$investigationId = bin2hex(random_bytes(12));
$scannedAt = (new DateTime())->format('Y-m-d H:i:s');

$store = [
    'headers' => $parsed,
    'raw' => substr($headersRaw, 0, 10000) // keep a truncated copy for privacy
];

if (isset($pdo) && $pdo instanceof PDO) {
    try {
        $stmt = $pdo->prepare('INSERT INTO scan_history (investigation_id, target, type, scanned_at, records, risk_score, risk_level, findings, limitations) VALUES (:investigation_id,:target,:type,:scanned_at,:records,:risk_score,:risk_level,:findings,:limitations)');
        $stmt->execute([
            ':investigation_id' => $investigationId,
            ':target' => $from ?: ($returnPath ?: 'unknown'),
            ':type' => 'email',
            ':scanned_at' => $scannedAt,
            ':records' => json_encode($store),
            ':risk_score' => $riskScore,
            ':risk_level' => $riskLevel,
            ':findings' => json_encode($findings),
            ':limitations' => json_encode($limitations),
        ]);
    } catch (Exception $e) {
        error_log('DB save email_analyze error: ' . $e->getMessage());
    }
} else {
    error_log('No DB connection available (email_analyze).');
}

http_response_code(200);
echo json_encode([
    'success' => true,
    'data' => [
        'scanned_at' => $scannedAt,
        'target' => $from,
        'risk_score' => $riskScore,
        'risk_level' => $riskLevel,
        'findings' => $findings,
        'limitations' => $limitations,
        'investigation_id' => $investigationId,
    ]
]);
