'use strict';

// ============================================================
// RECON UTILITIES — shared helpers for all recon tools
// ============================================================

const { exec } = require('child_process');
const https    = require('https');
const http     = require('http');
const crypto   = require('crypto');

const PYTHON = 'python';

function execTool(cmd, timeout) {
    return new Promise(function(resolve) {
        exec(cmd, { timeout: timeout || 120000 }, function(err, stdout, stderr) {
            const out = (stdout || '') + (stderr || '');
            resolve(out.trim() || (err
                ? `Error: ${err.message}${stderr ? '\nDetails: ' + stderr.trim().substring(0, 300) : ''}`
                : 'No output'));
        });
    });
}

function truncateOutput(output, maxChars) {
    if (!output || output.startsWith('Error:') || output.includes('not recognized')) {
        return 'Tool not available or returned no results.';
    }
    if (output.length <= maxChars) return output;
    return output.substring(0, maxChars) + '\n... [truncated]';
}

// Strip nmap hex fingerprint blocks — keep port table + useful script output
function cleanNmapOutput(output) {
    if (!output || output.startsWith('Error:') || output.includes('not recognized')) {
        return 'Tool not available or returned no results.';
    }
    const lines = output.split('\n');
    const kept  = [];
    let inFingerprintBlock = false;
    for (const line of lines) {
        const t = line.trim();
        if (!t) continue;
        if (t.startsWith('SF-') || /\\x[0-9a-f]{2}/i.test(t)) continue;
        if (t === 'fingerprint-strings:' || t === '| fingerprint-strings:') { inFingerprintBlock = true; continue; }
        if (inFingerprintBlock) {
            if (/^\d+\/(tcp|udp)/.test(t) || t.startsWith('Nmap') || t.startsWith('OS ')) inFingerprintBlock = false;
            else continue;
        }
        if (t.startsWith('Nmap scan report for')) { kept.push(t); continue; }
        if (t.startsWith('Host is')) { kept.push(t); continue; }
        if (/^\d+\/tcp\s+(open|closed|filtered)/.test(t) || /^\d+\/udp\s+(open|closed|filtered)/.test(t)) {
            if (/\bopen\b/.test(t)) kept.push(t);
            continue;
        }
        if (t.startsWith('OS details:') || t.startsWith('Running:') || t.startsWith('Service Info:')) { kept.push(t); continue; }
        if ((t.startsWith('|_') || t.startsWith('| ')) && !t.includes('%') && t.length < 200) {
            if (/^\|\s+(h2|http\/\d|http\/0)\s*$/.test(t)) continue;
            kept.push(t);
            continue;
        }
    }
    if (kept.length === 0) return 'Nmap: host unreachable or no open ports found.';
    return 'Nmap results:\n' + kept.join('\n');
}

// Strip ANSI escape codes, ASCII art banners, and tool boilerplate
function stripAnsiAndBanners(output) {
    if (!output || output.startsWith('Error:') || output.includes('not recognized')) {
        return 'Tool not available or returned no results.';
    }
    let cleaned = output;
    cleaned = cleaned.replace(/\x1b\[[0-9;]*m/g, '');
    cleaned = cleaned.replace(/\[[\d;]+m/g, '');
    cleaned = cleaned.replace(/\[\d+;\d+;\d+m/g, '');
    cleaned = cleaned.replace(/\[!\] legal disclaimer:[\s\S]*?(?:\r?\n){2}/gi, '');
    cleaned = cleaned.replace(/___[\s\S]*?https:\/\/sqlmap\.org\s*/gi, '');
    cleaned = cleaned.replace(/usage: jwt_tool\.py[\s\S]*?(?:No JWT provided|$)/i, 'No JWT provided');
    cleaned = cleaned.split('\n').filter(function(line) {
        const stripped = line.replace(/\s/g, '');
        if (stripped.length > 15 && /^[\\|/_\[\]{}#@~`'^*.\-=]+$/.test(stripped)) return false;
        return true;
    }).join('\n');
    cleaned = cleaned.replace(/(\r?\n){3,}/g, '\n\n');
    return cleaned.trim();
}

// Clean nuclei output — keep only actual finding lines
function cleanNucleiOutput(raw) {
    const lines    = raw.split('\n');
    const findings = [];
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed.startsWith('{')) {
            try {
                const obj = JSON.parse(trimmed);
                if (obj['template-id'] && obj['matched-at']) {
                    const sev  = (obj.info && obj.info.severity || 'info').toUpperCase();
                    let   name = (obj.info && obj.info.name) || obj['template-id'];
                    if (obj['matcher-name'] && !name.toLowerCase().includes(obj['matcher-name'].toLowerCase())) {
                        name = name + ': ' + obj['matcher-name'];
                    }
                    const cves   = (obj.info && obj.info.classification && obj.info.classification['cve-id']) || [];
                    const cveStr = cves.length ? ` CVE: ${cves.join(', ')}` : '';
                    findings.push(`[${sev}] ${name} — ${obj['matched-at']}${cveStr}`);
                }
            } catch (_) {
                if (/\[(medium|high|critical|low)\]/i.test(trimmed)) findings.push(trimmed);
            }
        } else if (/\[(info|low|medium|high|critical)\]/i.test(trimmed)) {
            findings.push(trimmed);
        }
    }
    if (findings.length === 0) return 'Nuclei: scan completed but no findings.';
    return `Nuclei findings (${findings.length}):\n` + findings.join('\n');
}

// Strip SQLMap banners/disclaimers — keep only actual findings
function cleanSqlmapOutput(output) {
    if (!output || output.startsWith('Error:') || output.includes('not recognized')) {
        return 'Tool not available or returned no results.';
    }
    let cleaned = stripAnsiAndBanners(output);
    cleaned = cleaned.split('\n').filter(function(line) {
        const t = line.trim();
        if (!t) return false;
        if (/^\[\*\] (starting|shutting down)/i.test(t)) return false;
        if (t.includes('DeprecationWarning')) return false;
        if (t.includes('_ctx.minimum_version')) return false;
        return true;
    }).join('\n').trim();
    if (!cleaned || cleaned.length < 20) {
        return 'SQLMap: scan completed but no SQL injection vulnerabilities detected.';
    }
    return cleaned;
}

// Strip FFuf progress lines/banners — keep only result lines
function cleanFFufOutput(raw) {
    if (!raw || raw.startsWith('Error:') || raw.includes('not recognized') || raw.includes('cannot find the path')) return raw;
    const lines = raw.split('\n').filter(function(line) {
        const t = line.trim();
        if (!t) return false;
        if (t.startsWith(':: ')) return false;
        if (t.startsWith("/'") || t.startsWith('/\\') || t.startsWith("\\'") || t.startsWith('\\')) return false;
        if (/^v\d+\./.test(t)) return false;
        if (/^_+$/.test(t)) return false;
        if (/^\|/.test(t) && !/Status:/.test(t)) return false;
        return true;
    });
    const found = lines.filter(function(l) { return /Status:/i.test(l) && !/Status:\s*(401|403)/i.test(l); });
    if (found.length === 0) return 'FFuf: no accessible paths discovered.';
    return `FFuf discovered paths (${found.length}):\n` + found.join('\n');
}

// Correctly parse any target format into host + port
function parseTarget(target) {
    let clean = target.replace(/^https?:\/\//, '');
    clean = clean.split('/')[0].split('?')[0];
    const lastColon = clean.lastIndexOf(':');
    if (lastColon !== -1 && /^\d+$/.test(clean.slice(lastColon + 1))) {
        return { host: clean.slice(0, lastColon), port: clean.slice(lastColon + 1) };
    }
    return { host: clean, port: null };
}

function getUrl(target) {
    if (target.startsWith('http://') || target.startsWith('https://')) return target;
    return 'http://' + target;
}

// Native HTTP/HTTPS probe — supports legacy TLS unlike fetch/undici
function probeFetch(url, timeoutMs) {
    return new Promise(function(resolve, reject) {
        const isHttps = url.startsWith('https');
        const mod     = isHttps ? https : http;
        const options = { method: 'HEAD', timeout: timeoutMs || 5000, rejectUnauthorized: false };
        if (isHttps) {
            options.minVersion   = 'TLSv1';
            options.ciphers      = 'DEFAULT:@SECLEVEL=0';
            options.secureOptions = (crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION || 0);
        }
        const req = mod.request(url, options, function(res) {
            resolve({ status: res.statusCode, location: res.headers.location || '' });
            res.resume();
        });
        req.on('error', reject);
        req.on('timeout', function() { req.destroy(); reject(new Error('Timeout')); });
        req.end();
    });
}

// Probe target to find best reachable URL (prefers HTTPS, supports HTTP-only)
async function probeTargetUrl(target) {
    const baseUrl = getUrl(target);
    const { host, port } = parseTarget(target);

    if (target.startsWith('https://')) return baseUrl;

    const httpsUrl = target.startsWith('http://')
        ? 'https://' + baseUrl.replace(/^http:\/\//, '')
        : 'https://' + (port ? `${host}:${port}` : host);

    try {
        const res = await probeFetch(httpsUrl, 8000);
        if (res.status < 400) {
            console.log(`[ZeroTrace] HTTPS available at ${httpsUrl} — using HTTPS`);
            return httpsUrl;
        }
    } catch (err) { console.warn('[ZeroTrace] HTTPS probe failed:', err.code || err.message); }

    try {
        const res = await probeFetch(baseUrl, 5000);
        if (res.status >= 300 && res.status < 400) {
            const location = res.location;
            if (location && !location.includes(host)) {
                console.warn(`[ZeroTrace] HTTP redirect to external host: ${location} — likely ISP hijack`);
                try {
                    const res2 = await probeFetch(httpsUrl, 8000);
                    if (res2.status < 400 || res2.status === 403) {
                        console.log(`[ZeroTrace] Falling back to HTTPS: ${httpsUrl}`);
                        return httpsUrl;
                    }
                } catch (err) { console.warn('[ZeroTrace] HTTPS fallback failed:', err.code || err.message); }
            }
        }
        console.log(`[ZeroTrace] Using HTTP: ${baseUrl}`);
    } catch (err) { console.warn('[ZeroTrace] HTTP probe failed:', err.code || err.message); }

    return baseUrl;
}

module.exports = {
    PYTHON, execTool, truncateOutput,
    cleanNmapOutput, cleanNucleiOutput, cleanSqlmapOutput, cleanFFufOutput,
    stripAnsiAndBanners, parseTarget, getUrl, probeFetch, probeTargetUrl
};
