<?php
// api/dns_scan.php
header('Content-Type: application/json; charset=utf-8');

// Basic limits and safety
$maxBody = 32 * 1024; // 32 KB
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Limit size
$cl = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : null;
if ($cl !== null && $cl > $maxBody) {
    http_response_code(413);
    echo json_encode(['success' => false, 'message' => 'Request too large']);
    exit;
}

$raw = file_get_contents('php://input');
if ($raw === false) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Empty request']);
    exit;
}
if (strlen($raw) > $maxBody) {
    http_response_code(413);
    echo json_encode(['success' => false, 'message' => 'Request too large']);
    exit;
}

$input = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Malformed JSON']);
    exit;
}

$domain = isset($input['domain']) ? trim((string)$input['domain']) : '';
if (empty($domain)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Domain required']);
    exit;
}

// Validate domain (use FILTER_VALIDATE_DOMAIN if available)
$validDomain = false;
if (defined('FILTER_VALIDATE_DOMAIN')) {
    $validDomain = (bool)filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
} else {
    // fallback regex (simple)
    $validDomain = (bool)preg_match('/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$/', $domain);
}
if (!$validDomain) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid domain']);
    exit;
}

require_once __DIR__ . '/../config/database.php';

// Helper to safely call dns_get_record and return simplified results
function safe_dns($domain, $type) {
    try {
        $result = @dns_get_record($domain, $type);
        if ($result === false) return [];
        return $result;
    } catch (Throwable $e) {
        error_log('dns error: ' . $e->getMessage());
        return [];
    }
}

$recordsRaw = [
    'A' => safe_dns($domain, DNS_A),
    'AAAA' => safe_dns($domain, DNS_AAAA),
    'MX' => safe_dns($domain, DNS_MX),
    'NS' => safe_dns($domain, DNS_NS),
    'TXT' => safe_dns($domain, DNS_TXT),
];

// normalize into simple arrays
$records = [
    'a' => array_map(function($r){ return $r['ip'] ?? null; }, $recordsRaw['A']),
    'aaaa' => array_map(function($r){ return $r['ipv6'] ?? null; }, $recordsRaw['AAAA']),
    'mx' => array_map(function($r){ return ['host'=>$r['target'] ?? $r['exchange'] ?? null, 'pri'=>$r['pri'] ?? $r['preference'] ?? null]; }, $recordsRaw['MX']),
    'ns' => array_map(function($r){ return $r['target'] ?? $r['host'] ?? null; }, $recordsRaw['NS']),
    'txt' => array_map(function($r){ return is_array($r['entries'] ?? null) ? implode("", $r['entries']) : ($r['txt'] ?? null); }, $recordsRaw['TXT']),
];

$spf = '';
foreach ($records['txt'] as $txt) {
    if (stripos((string)$txt, 'v=spf1') === 0) {
        $spf = $txt;
        break;
    }
}
$dmarcRecords = safe_dns('_dmarc.' . $domain, DNS_TXT);
$dmarc = '';
foreach ($dmarcRecords as $r) {
    $txt = is_array($r['entries'] ?? null) ? implode("", $r['entries']) : ($r['txt'] ?? null);
    if ($txt !== null) {
        $dmarc = $txt;
        break;
    }
}

// Heuristic risk scoring
$riskScore = 0;
$findings = [];
$limitations = [];

// SPF checks
if (empty($spf)) {
    $findings[] = 'No SPF record found.';
    $riskScore += 40;
} else {
    // common dangerous tokens
    $lc = strtolower($spf);
    if (strpos($lc, '+all') !== false) {
        $findings[] = "SPF record contains '+all' (very permissive)";
        $riskScore += 30;
    } elseif (strpos($lc, '~all') !== false) {
        $findings[] = "SPF record uses '~all' (softfail)";
        $riskScore += 10;
    } elseif (strpos($lc, '-all') !== false) {
        // good
    } else {
        $limitations[] = "SPF record present but no explicit all mekanism detected.";
        $riskScore += 5;
    }
}

// DMARC checks
if (empty($dmarc)) {
    $findings[] = 'No DMARC record found.';
    $riskScore += 30;
} else {
    $lc = strtolower($dmarc);
    if (strpos($lc, 'p=none') !== false) {
        $findings[] = 'DMARC policy set to p=none (monitoring only).';
        $riskScore += 10;
    } elseif (strpos($lc, 'p=quarantine') !== false) {
        // moderate
        $riskScore += 5;
    } elseif (strpos($lc, 'p=reject') !== false) {
        // good
    } else {
        $limitations[] = 'DMARC exists but policy not recognized.';
        $riskScore += 5;
    }
}

// Additional checks: missing MX for mail domains, etc.
if (empty($records['mx'])) {
    $limitations[] = 'No MX records found; domain may not receive mail.';
    $riskScore += 10;
}

// clamp score 0..100
$riskScore = max(0, min(100, (int)$riskScore));
$riskLevel = $riskScore >= 60 ? 'High' : ($riskScore >= 30 ? 'Moderate' : 'Low');

// build clean records object for storage
$storeRecords = [
    'a' => array_values(array_filter($records['a'])),
    'aaaa' => array_values(array_filter($records['aaaa'])),
    'mx' => array_values(array_filter(array_map(function($m){ return $m['host']; }, $records['mx']))),
    'ns' => array_values(array_filter($records['ns'])),
    'txt' => array_values(array_filter($records['txt'])),
    'spf' => $spf ?: null,
    'dmarc' => $dmarc ?: null,
];

// persist to DB
$investigationId = bin2hex(random_bytes(12));
$scannedAt = (new DateTime())->format('Y-m-d H:i:s');

if (isset($pdo) && $pdo instanceof PDO) {
    try {
        $stmt = $pdo->prepare('INSERT INTO scan_history (investigation_id, target, type, scanned_at, records, risk_score, risk_level, findings, limitations) VALUES (:investigation_id,:target,:type,:scanned_at,:records,:risk_score,:risk_level,:findings,:limitations)');
        $stmt->execute([
            ':investigation_id' => $investigationId,
            ':target' => $domain,
            ':type' => 'dns',
            ':scanned_at' => $scannedAt,
            ':records' => json_encode($storeRecords),
            ':risk_score' => $riskScore,
            ':risk_level' => $riskLevel,
            ':findings' => json_encode($findings),
            ':limitations' => json_encode($limitations),
        ]);
    } catch (Exception $e) {
        error_log('DB save dns_scan error: ' . $e->getMessage());
        // do not fail the overall response; continue returning results
    }
} else {
    error_log('No DB connection available (dns_scan).');
}

// Return normalized response (lowercase keys)
http_response_code(200);
echo json_encode([
    'success' => true,
    'data' => [
        'domain' => $domain,
        'scanned_at' => $scannedAt,
        'records' => $storeRecords,
        'risk_score' => $riskScore,
        'risk_level' => $riskLevel,
        'findings' => $findings,
        'limitations' => $limitations,
        'investigation_id' => $investigationId,
    ]
], JSON_UNESCAPED_SLASHES);
