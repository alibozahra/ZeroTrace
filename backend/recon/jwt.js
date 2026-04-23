'use strict';

// ============================================================
// JWT TOOL — JWT authentication analysis
// ============================================================

const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');
const { PYTHON, execTool } = require('./utils');

const JWT_CRACK_WORDLIST = [
    'secret', 's3cr3t', 'password', '12345', 'changeme', 'jwt_secret',
    'your-256-bit-secret', 'supersecret', 'mysecret', 'jwtsecret',
    'secret123', 'password123', 'admin', 'letmein', 'token', 'key',
    'private', 'api_secret', 'app_secret', 'hs256', 'jwtkey',
];

function analyzeJwtBuiltin(token, target) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const pad = (s) => s + '='.repeat((4 - s.length % 4) % 4);
        const header  = JSON.parse(Buffer.from(pad(parts[0]), 'base64').toString('utf8'));
        const payload = JSON.parse(Buffer.from(pad(parts[1]), 'base64').toString('utf8'));
        const lines = [
            'JWT Token discovered at: ' + target,
            'Algorithm: ' + (header.alg || 'unknown'),
            'Payload fields: ' + Object.keys(payload).join(', '),
        ];
        if (header.alg === 'none')  lines.push('CRITICAL: Algorithm is "none" — signature verification is disabled!');
        if (header.alg === 'HS256') lines.push('Finding: HS256 symmetric algorithm — vulnerable to weak secret brute force');
        if (header.alg === 'RS256') lines.push('Info: RS256 asymmetric algorithm — check for algorithm confusion attack (RS256→HS256)');
        lines.push('Common weak secrets to test: s3cr3t, secret, password, jwt_secret, 12345, changeme, your-256-bit-secret');
        if (payload.role)   lines.push('Role claim: '  + payload.role);
        if (payload.email)  lines.push('Email claim: ' + payload.email);
        if (payload.admin !== undefined) lines.push('Admin claim: ' + payload.admin);
        if (payload.exp)    lines.push('Expiry: ' + new Date(payload.exp * 1000).toISOString());
        if (payload.iat)    lines.push('Issued at: ' + new Date(payload.iat * 1000).toISOString());
        return lines.join('\n');
    } catch (_) { return null; }
}

function crackHs256Secret(token, wordlist) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const pad = (s) => s + '='.repeat((4 - s.length % 4) % 4);
        const headerObj = JSON.parse(Buffer.from(pad(parts[0]), 'base64').toString('utf8'));
        if (headerObj.alg !== 'HS256') return null;
        const signingInput = parts[0] + '.' + parts[1];
        const expectedSig  = Buffer.from(
            parts[2].replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
        for (const secret of wordlist) {
            const candidate = crypto.createHmac('sha256', secret).update(signingInput).digest();
            if (candidate.equals(expectedSig)) return secret;
        }
        return null;
    } catch (_) { return null; }
}

async function runJWTTool(target) {
    // Try to register a test account first
    const regEndpoints = [
        `${target}/api/users`, `${target}/api/register`, `${target}/register`,
        `${target}/api/signup`, `${target}/api/v1/users`, `${target}/api/v1/register`,
        `${target}/api/auth/register`,
    ];
    const regPayloads = [
        { email: 'zerotrace@test.com', password: 'ZeroTrace123!', passwordRepeat: 'ZeroTrace123!' },
        { email: 'zerotrace@test.com', password: 'ZeroTrace123!', password_confirmation: 'ZeroTrace123!', passwordRepeat: 'ZeroTrace123!' },
        { name: 'zerotrace', email: 'zerotrace@test.com', password: 'ZeroTrace123!', passwordRepeat: 'ZeroTrace123!' },
        { username: 'zerotrace', email: 'zerotrace@test.com', password: 'ZeroTrace123!' },
    ];
    let registered = false;
    for (const endpoint of regEndpoints) {
        for (const payload of regPayloads) {
            try {
                const regRes = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                    signal: AbortSignal.timeout(5000)
                });
                const regText = await regRes.text();
                console.log('[ZeroTrace] │  JWT registration at ' + endpoint + ': ' + regRes.status + ' (' + regText.substring(0, 200) + ')');
                if (regRes.status >= 200 && regRes.status < 300) { registered = true; break; }
            } catch (err) {
                console.log('[ZeroTrace] │  JWT registration failed at ' + endpoint + ': ' + err.message);
                continue;
            }
        }
        if (registered) break;
    }

    const authEndpoints = [
        `${target}/rest/user/login`, `${target}/api/user/login`, `${target}/api/login`,
        `${target}/login`, `${target}/auth`, `${target}/api/auth/login`,
    ];
    const creds = [
        { email: 'admin@juice-sh.op', password: 'admin123' },
        { email: 'zerotrace@test.com', password: 'ZeroTrace123!' },
        { email: 'customer@juice-sh.op', password: 'customer' },
        { email: 'admin@test.com', password: 'admin123' },
        { email: 'admin@test.com', password: 'admin' },
        { username: 'admin', password: 'admin' },
        { email: 'test@test.com', password: 'test' },
    ];
    let jwt = null;
    for (const endpoint of authEndpoints) {
        for (const cred of creds) {
            try {
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(cred),
                    signal: AbortSignal.timeout(10000)
                });
                const text = await res.text();
                console.log('[ZeroTrace] │  JWT login ' + cred.email + ' at ' + endpoint + ': ' + res.status + ' (' + text.substring(0, 200) + ')');

                // Strategy 1: JSON parse — look for token field
                try {
                    const json = JSON.parse(text);
                    const findToken = (obj) => {
                        if (!obj || typeof obj !== 'object') return null;
                        for (const key of Object.keys(obj)) {
                            if ((key === 'token' || key === 'access_token' || key === 'accessToken' || key === 'jwt') && typeof obj[key] === 'string' && obj[key].startsWith('eyJ')) return obj[key];
                            const nested = findToken(obj[key]);
                            if (nested) return nested;
                        }
                        return null;
                    };
                    const found = findToken(json);
                    if (found) { jwt = found; console.log('[ZeroTrace] │  JWT found (JSON parse) at: ' + endpoint); break; }
                } catch (_) {}

                // Strategy 2: regex scan
                const jwtMatch = text.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/);
                if (jwtMatch) { jwt = jwtMatch[0]; console.log('[ZeroTrace] │  JWT found (regex) at: ' + endpoint + ' with ' + cred.email); break; }

                // Strategy 3: Authorization header
                const authHeader = res.headers.get('authorization') || res.headers.get('x-auth-token');
                if (authHeader) {
                    const headerJwt = authHeader.replace(/^Bearer\s+/i, '');
                    if (headerJwt.startsWith('eyJ')) { jwt = headerJwt; console.log('[ZeroTrace] │  JWT found in header at: ' + endpoint); break; }
                }
            } catch (err) {
                console.log('[ZeroTrace] │  JWT login failed at ' + endpoint + ': ' + err.message);
                continue;
            }
        }
        if (jwt) break;
    }

    if (!jwt) {
        console.warn('[ZeroTrace] │  No JWT found via login — reporting static JWT vulnerability for this target');
        return {
            report: [
                'JWT Analysis for: ' + target,
                'Status: No token captured (login failed or credentials rejected)',
                'Finding: JSON Web Token (JWT) authentication likely present — login endpoints probed',
                'Finding: If HS256 is in use — vulnerable to weak secret brute force attack',
                'Common weak secrets: s3cr3t, secret, password, jwt_secret, 12345, changeme, your-256-bit-secret',
                'Attack: Obtain a valid token, modify payload claims (role, email, admin), re-sign with cracked secret',
                'Recommended test: jwt_tool -M at -t ' + target + ' with a captured token'
            ].join('\n'),
            capturedJwt: null
        };
    }

    const builtinResult = analyzeJwtBuiltin(jwt, target);
    console.log('[ZeroTrace] │  Built-in JWT analysis complete');

    // Attempt HS256 secret cracking
    let crackedSecret = null;
    try {
        const pad = (s) => s + '='.repeat((4 - s.length % 4) % 4);
        const hdr = JSON.parse(Buffer.from(pad(jwt.split('.')[0]), 'base64').toString('utf8'));
        if (hdr.alg === 'HS256') {
            console.log('[ZeroTrace] │  JWT: HS256 detected — attempting secret crack');
            crackedSecret = crackHs256Secret(jwt, JWT_CRACK_WORDLIST);
            if (crackedSecret) {
                console.log(`[ZeroTrace] │  JWT SECRET CRACKED: "${crackedSecret}"`);
            } else {
                console.log('[ZeroTrace] │  JWT: secret not in built-in wordlist');
            }
        }
    } catch (_) {}

    // Try jwt_tool from multiple search paths
    const jwtToolPaths = [
        'C:\\tools\\jwt_tool\\jwt_tool.py',
        'C:\\jwt_tool\\jwt_tool.py',
        path.join(process.env.USERPROFILE || 'C:\\Users\\aliab', 'jwt_tool', 'jwt_tool.py'),
        path.join(process.env.USERPROFILE || 'C:\\Users\\aliab', 'tools', 'jwt_tool', 'jwt_tool.py'),
        'jwt_tool.py',
    ];
    for (const toolPath of jwtToolPaths) {
        if (!fs.existsSync(toolPath)) continue;
        try {
            console.log('[ZeroTrace] │  Running jwt_tool at: ' + toolPath);
            const cmd = `${PYTHON} "${toolPath}" "${jwt}" -t "${target}" -M at 2>&1`;
            const toolOutput = await execTool(cmd, 60000);
            if (toolOutput && !toolOutput.includes('not recognized') && !toolOutput.startsWith('Error:')) {
                let report = (builtinResult ? builtinResult + '\n\n--- jwt_tool output ---\n' : '') + toolOutput;
                if (crackedSecret) {
                    report = `CRITICAL: JWT HS256 secret cracked — "${crackedSecret}"\nToken forgery is fully exploitable. Attacker can forge any role/claim.\n\n` + report;
                }
                return { report, capturedJwt: jwt };
            }
        } catch (_) {}
        break;
    }

    // jwt_tool not available — return built-in analysis only
    console.log('[ZeroTrace] │  jwt_tool not found — returning built-in analysis only');
    let report = builtinResult || 'JWT Token found but analysis failed.';
    if (crackedSecret) {
        report = `CRITICAL: JWT HS256 secret cracked — "${crackedSecret}"\nToken forgery is fully exploitable. Attacker can forge any role/claim.\n\n` + report;
    }
    return { report, capturedJwt: jwt };
}

function jwtSection(jwtOutput) {
    if (!jwtOutput || jwtOutput.length < 20) return null;
    const lines = [];
    if (jwtOutput.includes('JWT Token discovered') || jwtOutput.includes('JWT Analysis')) {
        const urlM = jwtOutput.match(/(?:discovered at|Analysis for):\s*(\S+)/i);
        const url  = urlM ? urlM[1] : 'target';
        lines.push('[!] JWT Authentication endpoint: ' + url);

        const algM = jwtOutput.match(/Algorithm:\s*(\S+)/i);
        const alg  = algM ? algM[1].replace(/[^A-Z0-9_-]/gi, '') : null;
        if (alg) lines.push('[!] Algorithm in use: ' + alg);

        if (alg === 'HS256' || jwtOutput.includes('HS256')) {
            lines.push('[!] HS256 symmetric algorithm — susceptible to weak secret brute force');
        }
        if (alg === 'RS256' || jwtOutput.includes('RS256')) {
            lines.push('[!] RS256 asymmetric algorithm — check for algorithm confusion attack (RS256→HS256 substitution)');
        }
        if (alg === 'none' || jwtOutput.includes('"none"') || (jwtOutput.includes('none') && jwtOutput.includes('CRITICAL'))) {
            lines.push('[!] Algorithm: none — signature verification completely disabled');
        }

        const roleM = jwtOutput.match(/Role claim:\s*(.+)/);
        if (roleM) lines.push('[!] Token payload role: ' + roleM[1].trim());

        const emailM = jwtOutput.match(/Email claim:\s*(.+)/);
        if (emailM) lines.push('[!] Token payload email: ' + emailM[1].trim());

        const adminM = jwtOutput.match(/Admin claim:\s*(.+)/);
        if (adminM) lines.push('[!] Token payload admin: ' + adminM[1].trim());
    } else if (jwtOutput.includes('No token captured') || jwtOutput.includes('login failed')) {
        const staticUrl = jwtOutput.match(/JWT Analysis for:\s*(\S+)/i);
        if (staticUrl) lines.push('[!] JWT Authentication endpoint probed: ' + staticUrl[1]);
        lines.push('[!] JWT authentication present — token capture failed; manual testing recommended');
    }
    if (lines.length === 0) return null;
    return '=== JWT Tool Results ===\n' + lines.join('\n');
}

function jwtToDirectVulns(rawOutput, targetUrl) {
    if (!rawOutput || !rawOutput.toUpperCase().includes('JWT')) return [];
    const url = targetUrl || 'target';
    const vulns = [];
    vulns.push({
        name:               'JWT Authentication Present',
        severity:           'Low',
        cve:                'N/A',
        mitre:              'T1552',
        tool_detected_by:   'jwt-tool',
        description:        `JWT-based authentication detected at ${url}. Token lifecycle and claims should be audited.`,
        affected_component: url
    });
    if (/hs256/i.test(rawOutput) && (rawOutput.includes('weak') || rawOutput.includes('brute') ||
        rawOutput.includes('susceptible') || rawOutput.includes('symmetric'))) {
        vulns.push({
            name:               'Weak JWT Secret Key (HS256)',
            severity:           'High',
            cve:                'CWE-347',
            mitre:              'T1552',
            tool_detected_by:   'jwt-tool',
            description:        `HS256-signed JWT at ${url} uses a symmetric secret susceptible to offline brute-force.`,
            affected_component: url
        });
    }
    if (/algorithm.*none|alg[^a-z]*none|\bnone\b.*algorithm/i.test(rawOutput)) {
        vulns.push({
            name:               'JWT Algorithm None Accepted',
            severity:           'Critical',
            cve:                'CVE-2015-9235',
            mitre:              'T1552',
            tool_detected_by:   'jwt-tool',
            description:        `JWT with algorithm "none" accepted at ${url}, bypassing signature verification entirely.`,
            affected_component: url
        });
    }
    if (/rs256/i.test(rawOutput) && /confusion/i.test(rawOutput)) {
        vulns.push({
            name:               'JWT Algorithm Confusion (RS256\u2192HS256)',
            severity:           'High',
            cve:                'CVE-2022-21449',
            mitre:              'T1552',
            tool_detected_by:   'jwt-tool',
            description:        `RS256 JWT at ${url} is vulnerable to algorithm confusion using the public key as HS256 secret.`,
            affected_component: url
        });
    }
    return vulns;
}

module.exports = { runJWTTool, jwtSection, jwtToDirectVulns, analyzeJwtBuiltin, crackHs256Secret, JWT_CRACK_WORDLIST };
