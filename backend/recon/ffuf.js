'use strict';

// ============================================================
// FFUF — directory and API endpoint discovery
// ============================================================

const path = require('path');
const fs   = require('fs');
const { execTool, probeFetch } = require('./utils');

async function runFFuf(target) {
    const wordlists = [
        'C:\\tools\\wordlists\\common.txt',
        'C:\\tools\\SecLists\\Discovery\\Web-Content\\common.txt',
        path.join(process.env.USERPROFILE || '', 'tools', 'wordlists', 'common.txt'),
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
    ];
    let wordlist = null;
    for (const w of wordlists) {
        if (fs.existsSync(w)) { wordlist = w; break; }
    }
    if (!wordlist) {
        console.warn('[ZeroTrace] │  No wordlist found for FFuf — skipping');
        return 'FFuf: no wordlist found. Install SecLists or dirb wordlists.';
    }

    // Probe baseline response size so we can filter SPA index.html false positives
    let spaSize = null;
    try {
        const probe = await probeFetch(`${target}/zt-nonexistent-probe-path`, 5000);
        if (probe.status === 200) {
            const r = await fetch(`${target}/zt-nonexistent-probe-path`, { signal: AbortSignal.timeout(5000) });
            const body = await r.text();
            spaSize = body.length;
            console.log(`[ZeroTrace] │  FFuf SPA baseline size: ${spaSize}`);
        }
    } catch (_) {}

    const fsFlag = spaSize ? ` -fs ${spaSize}` : '';
    const allRaw = [];

    // Pass 1: root path discovery
    const cmd1 = `ffuf -u "${target}/FUZZ" -w "${wordlist}" -mc 200,201,204,301,302 -s -t 40 -timeout 10 -maxtime 60${fsFlag}`;
    const raw1 = await execTool(cmd1, 90000);
    if (raw1 && !raw1.startsWith('Error:')) allRaw.push(raw1);

    // Pass 2: /api/ sub-paths
    const cmd2 = `ffuf -u "${target}/api/FUZZ" -w "${wordlist}" -mc 200,201,204 -s -t 40 -timeout 10 -maxtime 60`;
    const raw2 = await execTool(cmd2, 90000);
    if (raw2 && !raw2.startsWith('Error:')) allRaw.push(raw2);

    // Pass 3: /rest/ sub-paths
    const cmd3 = `ffuf -u "${target}/rest/FUZZ" -w "${wordlist}" -mc 200,201,204 -s -t 40 -timeout 10 -maxtime 60`;
    const raw3 = await execTool(cmd3, 90000);
    if (raw3 && !raw3.startsWith('Error:')) allRaw.push(raw3);

    // Pass 4: parameter name fuzzing on known API paths
    const paramWordlists = [
        'C:\\tools\\SecLists\\Discovery\\Web-Content\\burp-parameter-names.txt',
        path.join(process.env.USERPROFILE || '', 'tools', 'SecLists', 'Discovery', 'Web-Content', 'burp-parameter-names.txt'),
        '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
    ];
    let paramWordlist = null;
    for (const w of paramWordlists) { if (fs.existsSync(w)) { paramWordlist = w; break; } }
    if (paramWordlist) {
        const apiPaths = ['/api/products', '/api/users', '/api/search', '/search', '/rest/products'];
        for (const apiPath of apiPaths) {
            const cmd4 = `ffuf -u "${target}${apiPath}?FUZZ=1" -w "${paramWordlist}" -mc 200,201,204,400,500 -s -t 20 -timeout 8 -maxtime 30`;
            const raw4 = await execTool(cmd4, 45000);
            if (raw4 && !raw4.startsWith('Error:') && raw4.trim()) {
                allRaw.push(`[Pass 4 - ${apiPath} params]\n` + raw4);
            }
        }
    }

    const ffufResult = cleanFFufOutput(allRaw.join('\n'));

    // Fallback: directly probe common web/REST API paths
    if (ffufResult.includes('no accessible paths') || ffufResult.includes('No results')) {
        console.log('[ZeroTrace] │  FFuf found nothing — probing common web endpoints directly');
        const knownPaths = [
            '/api/users', '/api/user', '/api/admin', '/api/products', '/api/items', '/api/login',
            '/api/v1/users', '/api/v1/login', '/api-docs/swagger.json', '/api-docs',
            '/swagger.json', '/openapi.json', '/swagger/index.html', '/v2/api-docs',
            '/metrics', '/health', '/healthz', '/robots.txt', '/admin', '/login', '/register',
            '/actuator/health', '/actuator/env', '/config.json', '/phpinfo.php', '/server-status',
            '/rest/products/search', '/rest/user/login', '/rest/user/whoami', '/rest/basket',
            '/rest/products', '/api/SecurityQuestion', '/api/Challenges', '/redirect', '/ftp', '/encryptionkeys',
        ];
        const found = [];
        for (const p of knownPaths) {
            try {
                const r = await fetch(`${target}${p}`, { signal: AbortSignal.timeout(5000), redirect: 'follow' });
                if (r.status === 200 || r.status === 201 || r.status === 204 ||
                    r.status === 400 || r.status === 401 || r.status === 403) {
                    const ct = r.headers.get('content-type') || '';
                    const type = ct.includes('json') ? 'JSON' : ct.includes('html') ? 'HTML' : ct.includes('yaml') ? 'YAML' : 'TEXT';
                    const authNote = (r.status === 401 || r.status === 403) ? ', Requires-Auth' : '';
                    found.push(`${p} [Status: ${r.status}, Type: ${type}${authNote}]`);
                }
            } catch (_) {}
        }
        if (found.length > 0) {
            return `FFuf discovered paths (${found.length}):\n` + found.join('\n');
        }
    }
    return ffufResult;
}

function cleanFFufOutput(raw) {
    if (!raw || raw.startsWith('Error:') || raw.includes('not recognized') || raw.includes('cannot find the path')) return raw;
    const found = [];
    for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (/Status:/i.test(trimmed)) {
            if (/Status:\s*(401|403)/i.test(trimmed)) continue;
            found.push(trimmed);
        }
    }
    if (found.length === 0) return 'FFuf: no accessible paths discovered.';
    return `FFuf discovered paths (${found.length}):\n` + found.join('\n');
}

function ffufSection(ffufOutput) {
    if (!ffufOutput || !ffufOutput.includes('Status:')) return null;
    const lines = [];
    ffufOutput.split('\n').forEach(function(l) {
        const m = l.match(/^(\S+)\s+\[Status:\s*(\d+)[^\]]*?(?:,\s*Type:\s*(\w+))?/);
        if (m) {
            const type = m[3] ? ', Type: ' + m[3] : '';
            lines.push(m[1] + '  (Status: ' + m[2] + type + ')');
        }
    });
    if (lines.length === 0) return null;
    return '=== FFUF Results ===\n' + lines.join('\n');
}

module.exports = { runFFuf, ffufSection, cleanFFufOutput };
