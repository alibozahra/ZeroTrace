'use strict';

// ============================================================
// API SCANNER — built-in REST API security scanner (fetch only)
// ============================================================

async function runApiScanner(target) {
    const findings = [];

    // Test 0: HTTP Security Headers
    try {
        const r = await fetch(target, { signal: AbortSignal.timeout(8000) });
        const REQUIRED_HEADERS = [
            ['content-security-policy',          'Content-Security-Policy Missing'],
            ['x-frame-options',                  'X-Frame-Options Missing'],
            ['x-content-type-options',           'X-Content-Type-Options Missing'],
            ['strict-transport-security',        'Strict-Transport-Security (HSTS) Missing'],
            ['referrer-policy',                  'Referrer-Policy Missing'],
            ['permissions-policy',               'Permissions-Policy Missing'],
            ['cross-origin-opener-policy',       'Cross-Origin-Opener-Policy Missing'],
            ['cross-origin-resource-policy',     'Cross-Origin-Resource-Policy Missing'],
            ['cross-origin-embedder-policy',     'Cross-Origin-Embedder-Policy Missing'],
            ['x-permitted-cross-domain-policies','X-Permitted-Cross-Domain-Policies Missing'],
        ];
        for (const [header, label] of REQUIRED_HEADERS) {
            if (!r.headers.get(header)) {
                findings.push(`[LOW] ${label} — ${target}`);
            }
        }
    } catch (_) {}

    // Test 1: CORS misconfiguration
    try {
        const r = await fetch(target, { headers: { 'Origin': 'https://evil.com' }, signal: AbortSignal.timeout(5000) });
        const acao = r.headers.get('access-control-allow-origin');
        if (acao === '*') findings.push(`[HIGH] CORS Wildcard — ${target}: Access-Control-Allow-Origin: *`);
        else if (acao === 'https://evil.com') findings.push(`[HIGH] CORS Misconfiguration — ${target}: reflects arbitrary Origin`);
    } catch (_) {}

    // Test 2: Dangerous HTTP methods via OPTIONS
    try {
        const r = await fetch(target, { method: 'OPTIONS', signal: AbortSignal.timeout(5000) });
        const allow = r.headers.get('access-control-allow-methods') || r.headers.get('allow') || '';
        if (/DELETE|PUT|PATCH/i.test(allow)) {
            findings.push(`[MEDIUM] Dangerous HTTP Methods Allowed — ${target}: ${allow}`);
        }
    } catch (_) {}

    // Test 3: Server/technology version disclosure
    try {
        const r = await fetch(target, { signal: AbortSignal.timeout(5000) });
        const server  = r.headers.get('server') || '';
        const powered = r.headers.get('x-powered-by') || '';
        if (server)  findings.push(`[LOW] Server Version Disclosure — ${target}: Server: ${server}`);
        if (powered) findings.push(`[LOW] Technology Disclosure — ${target}: X-Powered-By: ${powered}`);
    } catch (_) {}

    // Test 4: IDOR — unauthenticated access to user objects
    const idorPaths = ['/api/users/1', '/api/Users/1', '/rest/user/1', '/api/user/1'];
    for (const p of idorPaths) {
        try {
            const r = await fetch(`${target}${p}`, { signal: AbortSignal.timeout(5000) });
            if (r.status === 200) {
                const body = await r.text();
                if (body.includes('@') || body.includes('email') || body.includes('password')) {
                    findings.push(`[HIGH] IDOR — ${target}${p}: User PII exposed without authentication`);
                    break;
                }
            }
        } catch (_) {}
    }

    // Test 5: Sensitive endpoint exposure (body-validated to avoid SPA false positives)
    const sensitiveEndpoints = [
        ['/metrics',               'MEDIUM',  'Prometheus Metrics Exposed',
            function(ct, body) { return ct.includes('text/plain') || body.includes('# HELP') || body.includes('go_goroutines'); }],
        ['/api-docs',              'LOW',     'Swagger API Documentation Exposed',
            function(_ct, body) { return body.toLowerCase().includes('swagger'); }],
        ['/api-docs/swagger.json', 'LOW',     'Swagger JSON Exposed',
            function(ct, body) { return ct.includes('json') || body.trim().startsWith('{'); }],
        ['/ftp',                   'HIGH',    'FTP Directory Listing Exposed',
            function(ct, body) { return !ct.includes('text/html') || (body.length < 20000 && (body.toLowerCase().includes('backup') || body.toLowerCase().includes('directory'))); }],
        ['/encryptionkeys',        'CRITICAL','Encryption Keys Directory Exposed',
            function(ct, body) { return !ct.includes('text/html') || (body.length < 20000 && body.toLowerCase().includes('key')); }],
        ['/.git/HEAD',             'HIGH',    'Git Repository Exposed',
            function(_ct, body) { return body.trim().startsWith('ref:'); }],
        ['/phpinfo.php',           'MEDIUM',  'PHP Info Page Exposed',
            function(_ct, body) { return body.includes('PHP Version') || body.includes('phpinfo()'); }],
        ['/server-status',         'MEDIUM',  'Apache Server Status Exposed',
            function(_ct, body) { return body.includes('Apache') && body.includes('requests'); }],
        ['/actuator/env',          'HIGH',    'Spring Boot Actuator Environment Exposed',
            function(ct, body) { return ct.includes('json') && body.includes('activeProfiles'); }],
    ];
    for (const [p, sev, label, validate] of sensitiveEndpoints) {
        try {
            const r = await fetch(`${target}${p}`, { signal: AbortSignal.timeout(5000) });
            if (r.status === 200) {
                const ct   = r.headers.get('content-type') || '';
                const body = await r.text();
                if (validate(ct, body)) {
                    findings.push(`[${sev}] ${label} — ${target}${p}`);
                }
            }
        } catch (_) {}
    }

    if (findings.length === 0) return 'API Scanner: no findings.';
    return `API Scanner findings (${findings.length}):\n` + findings.join('\n');
}

module.exports = { runApiScanner };
