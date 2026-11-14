<?php
/**
 * 订阅链接拉取端点（供 /tools/proxy/ 前端使用）
 *
 * GET /tools/proxy/fetch.php?url=<订阅地址>
 *   -> 200 text/plain  原始内容（前端负责解析）
 *
 * 安全边界（这是公网端点，必须按 SSRF 对待）：
 *   1. 只允许 http / https
 *   2. 解析后的 IP 必须是公网地址（拒绝 10/8、172.16/12、192.168/16、127/8、
 *      169.254/16、100.64/10、::1、fc00::/7、fe80::/10 等）
 *   3. 禁止跟随重定向到内网（每一跳都重新校验）
 *   4. 15 秒超时、2MB 上限、只返回文本，不落盘
 *   5. 限频：同 IP 每分钟 20 次
 */
declare(strict_types=1);

header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function fail(int $code, string $msg): void
{
    http_response_code($code);
    echo $msg;
    exit;
}

/* ---------- 限频 ---------- */
$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$bucket = sys_get_temp_dir() . '/pxfetch_' . md5($ip);
$now = time();
$hits = [];
if (is_file($bucket)) {
    $raw = @file_get_contents($bucket);
    $hits = $raw ? (array)json_decode($raw, true) : [];
}
$hits = array_values(array_filter($hits, static fn($t) => $t > $now - 60));
if (count($hits) >= 20) {
    fail(429, '请求过于频繁，请稍后再试');
}
$hits[] = $now;
@file_put_contents($bucket, json_encode($hits), LOCK_EX);

/* ---------- 参数 ---------- */
$url = trim((string)($_GET['url'] ?? ''));
if ($url === '') {
    fail(400, '缺少参数 url');
}
if (strlen($url) > 2048) {
    fail(400, 'url 过长');
}

$scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
if (!in_array($scheme, ['http', 'https'], true)) {
    fail(400, '只支持 http / https');
}

/** 判断 IP 是否公网（false = 内网/保留，必须拒绝） */
function isPublicIp(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    // 额外挡住 CGNAT 与 IPv6 ULA / link-local
    $packed = inet_pton($ip);
    if ($packed === false) {
        return false;
    }
    if (strlen($packed) === 4) {
        $long = ip2long($ip);
        if ($long >= ip2long('100.64.0.0') && $long <= ip2long('100.127.255.255')) {
            return false;
        }
    }
    return true;
}

/** 校验 URL 的主机解析结果；返回小写 host 或 null */
function checkHost(string $url): ?string
{
    $host = strtolower((string)parse_url($url, PHP_URL_HOST));
    if ($host === '') {
        return null;
    }
    if ($host === 'localhost' || str_ends_with($host, '.localhost') || str_ends_with($host, '.internal')) {
        return null;
    }
    // 已经是 IP 字面量
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return isPublicIp($host) ? $host : null;
    }
    $ips = @gethostbynamel($host) ?: [];
    // 有 AAAA 记录的也查一遍
    $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];
    foreach ($aaaa as $r) {
        if (!empty($r['ipv6'])) {
            $ips[] = $r['ipv6'];
        }
    }
    if (!$ips) {
        return null;
    }
    foreach ($ips as $ip) {
        if (!isPublicIp($ip)) {
            return null; // 解析到任何一个内网地址就整体拒绝
        }
    }
    return $host;
}

if (checkHost($url) === null) {
    fail(400, '目标地址不允许（内网或无法解析）');
}

/* ---------- 抓取 ---------- */
$hops = 0;
$current = $url;
$body = '';

for ($i = 0; $i < 4; $i++) {
    if (checkHost($current) === null) {
        fail(400, '重定向到不允许的地址');
    }
    $ch = curl_init($current);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => [
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
            'Accept: */*',
        ],
        CURLOPT_MAXFILESIZE => 2 * 1024 * 1024,
    ]);
    $resp = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $loc = (string)curl_getinfo($ch, CURLINFO_REDIRECT_URL);
    $err = curl_error($ch);
    curl_close($ch);

    if ($resp === false || $err !== '') {
        fail(502, '抓取失败: ' . $err);
    }
    if ($code >= 300 && $code < 400 && $loc !== '') {
        $current = $loc;
        $hops++;
        continue;
    }
    if ($code !== 200) {
        fail(502, '目标返回 HTTP ' . $code);
    }
    $body = (string)$resp;
    break;
}

if ($body === '') {
    fail(502, '没有拿到内容（重定向过多或内容为空）');
}
if (strlen($body) > 2 * 1024 * 1024) {
    fail(413, '内容超过 2MB');
}

echo $body;
