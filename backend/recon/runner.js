'use strict';

// ============================================================
// RECON RUNNER — orchestrates all 7 recon tools sequentially
// ============================================================

const path = require('path');
const fs   = require('fs');
const https = require('https');
const http  = require('http');

const { cleanNmapOutput, probeTargetUrl, parseTarget } = require('./utils');
const { runNmap }                         = require('./nmap');
const { runNuclei, runNucleiAuthenticated } = require('./nuclei');
const { runFFuf }                         = require('./ffuf');
const { runSQLMap }                       = require('./sqlmap');
const { runJWTTool }                      = require('./jwt');
const { runApiScanner }                   = require('./apiScanner');
const { LOGS_DIR }                        = require('../sessions');

// Metasploit RPC constants
const MSF_HOST = process.env.MSF_RPC_HOST || '127.0.0.1';
const MSF_PORT = parseInt(process.env.MSF_RPC_PORT || '55553', 10);
const MSF_PASS = process.env.MSF_RPC_PASS || 'zerotrace123';
const MSF_SSL  = (process.env.MSF_RPC_SSL || 'true') !== 'false';
let   msfToken = null;

function msfrpcCall(method) {
    const extraArgs = Array.prototype.slice.call(arguments, 1);
    return new Promise(function(resolve, reject) {
        const body = JSON.stringify([method].concat(extraArgs));
        const mod  = MSF_SSL ? https : http;
        const opts = {
            hostname: MSF_HOST, port: MSF_PORT, path: '/api/1.0/', method: 'POST',
            rejectUnauthorized: false,
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
        };
        const req = mod.request(opts, function(res) {
            let data = '';
            res.on('data', function(c) { data += c; });
            res.on('end', function() {
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(new Error('MSF RPC parse error: ' + data.substring(0, 200))); }
            });
        });
        req.on('error', reject);
        req.setTimeout(20000, function() { req.destroy(); reject(new Error('MSF RPC timeout')); });
        req.write(body);
        req.end();
    });
}

async function msfLogin() {
    const res = await msfrpcCall('auth.login', 'msf', MSF_PASS);
    if (res && res.result === 'success' && res.token) {
        msfToken = res.token;
        console.log('[MSF] RPC authenticated');
        return true;
    }
    throw new Error('MSF RPC auth failed: ' + JSON.stringify(res));
}

async function msfConnect() {
    if (msfToken) {
        try {
            const res = await msfrpcCall('core.version', msfToken);
            if (res && !res.error) return true;
        } catch (_) {}
        msfToken = null;
    }
    try { await msfLogin(); return true; }
    catch (err) { console.warn('[MSF] Cannot connect to msfrpcd:', err.message); return false; }
}

async function runMetasploit(target) {
    const { host, port } = parseTarget(target);
    const rport = port || (target.startsWith('https') ? '443' : '80');
    const ssl   = target.startsWith('https') ? 'true' : 'false';

    console.log('[ZeroTrace] │  Connecting to Metasploit RPC...');
    const ok = await msfConnect();
    if (!ok) {
        return 'Metasploit: msfrpcd is not running. ' +
               'Start it with: msfrpcd -P zerotrace123 -a 127.0.0.1 -f\n' +
               'Install Metasploit (Windows): winget install Rapid7.Metasploit';
    }

    let consoleId;
    try {
        const cr = await msfrpcCall('console.create', msfToken);
        consoleId = cr.id;
        console.log(`[ZeroTrace] │  MSF console ${consoleId} opened`);
    } catch (err) { return 'Metasploit: failed to create console — ' + err.message; }

    const cmds = [
        'use auxiliary/scanner/http/http_version',
        'set RHOSTS ' + host, 'set RPORT ' + rport, 'set SSL ' + ssl, 'run',
        'use auxiliary/scanner/http/robots_txt',
        'set RHOSTS ' + host, 'set RPORT ' + rport, 'set SSL ' + ssl, 'run',
        'use auxiliary/scanner/http/options',
        'set RHOSTS ' + host, 'set RPORT ' + rport, 'set SSL ' + ssl, 'run',
        'use auxiliary/scanner/http/backup_file',
        'set RHOSTS ' + host, 'set RPORT ' + rport, 'set SSL ' + ssl, 'run',
        'exit',
    ].join('\n') + '\n';

    try {
        await msfrpcCall('console.write', msfToken, consoleId, cmds);
    } catch (err) {
        await msfrpcCall('console.destroy', msfToken, consoleId).catch(function() {});
        return 'Metasploit: failed to write commands — ' + err.message;
    }

    let output = '';
    let idleRuns = 0;
    for (let i = 0; i < 60; i++) {
        await new Promise(function(r) { setTimeout(r, 2000); });
        try {
            const read = await msfrpcCall('console.read', msfToken, consoleId);
            if (read.data) { output += read.data; idleRuns = 0; }
            else            { idleRuns++; }
            if (!read.busy && idleRuns >= 2) break;
        } catch (err) { console.warn('[MSF] console.read error:', err.message); break; }
    }

    await msfrpcCall('console.destroy', msfToken, consoleId).catch(function() {});
    console.log(`[ZeroTrace] │  MSF console ${consoleId} closed, output: ${output.length} chars`);
    return output || 'Metasploit: modules ran but produced no output.';
}

async function safeRunTool(toolName, toolFn) {
    const start = Date.now();
    console.log(`\n[ZeroTrace] ┌─ RECON TOOL: ${toolName}`);
    console.log(`[ZeroTrace] │  Started: ${new Date().toISOString()}`);
    try {
        const output  = await toolFn();
        const runtime = ((Date.now() - start) / 1000).toFixed(1);
        const outLen  = typeof output === 'string' ? output.length : JSON.stringify(output).length;
        console.log(`[ZeroTrace] │  Runtime: ${runtime}s`);
        console.log(`[ZeroTrace] │  Output: ${outLen} chars`);
        console.log(`[ZeroTrace] └─ ${toolName} COMPLETE (${runtime}s)`);
        return { output, runtime, status: 'complete' };
    } catch (err) {
        const runtime = ((Date.now() - start) / 1000).toFixed(1);
        console.warn(`[ZeroTrace] └─ ${toolName} FAILED (${runtime}s): ${err.message}`);
        return { output: `${toolName}: failed — ${err.message}`, runtime, status: 'failed' };
    }
}

// Clean tool outputs before sending to zerotrace-v2
function cleanForAnalysis(raw) {
    return {
        nmap:       cleanNmapOutput(raw.nmap || ''),
        nuclei:     raw.nuclei     || '',
        ffuf:       raw.ffuf       || '',
        sqlmap:     raw.sqlmap     || '',
        jwt:        raw.jwt        || '',
        nucleiAuth: raw.nucleiAuth || '',
        apiScan:    raw.apiScan    || '',
        metasploit: raw.metasploit || '',
    };
}

async function runAllRecon(target, scanType, sessionId) {
    const targetUrl = await probeTargetUrl(target);

    console.log('\n════════════════════════════════════════');
    console.log('STEP 1 — RECONNAISSANCE (6 tools)');
    console.log(`[RECON] Target: ${target}  Resolved URL: ${targetUrl}  ScanType: ${scanType}`);
    console.log('════════════════════════════════════════');

    const nmap       = await safeRunTool('Nmap',        () => runNmap(target, scanType));
    const nuclei     = await safeRunTool('Nuclei',      () => runNuclei(targetUrl));
    const ffuf       = await safeRunTool('FFuf',        () => runFFuf(targetUrl));
    const sqlmap     = await safeRunTool('SQLMap',      () => runSQLMap(targetUrl, ffuf.output));
    const jwtRaw     = await safeRunTool('JWT Tool',    () => runJWTTool(targetUrl));
    const apiScan    = await safeRunTool('API Scanner', () => runApiScanner(targetUrl));
    const metasploit = await safeRunTool('Metasploit',  () => runMetasploit(targetUrl));

    // Unwrap JWT result — runJWTTool returns { report, capturedJwt }
    const jwtReport   = (jwtRaw.output && typeof jwtRaw.output === 'object')
        ? (jwtRaw.output.report || '')
        : String(jwtRaw.output || '');
    const capturedJwt = (jwtRaw.output && typeof jwtRaw.output === 'object')
        ? (jwtRaw.output.capturedJwt || null)
        : null;

    const nucleiAuth = await safeRunTool('Nuclei (Auth)', () => runNucleiAuthenticated(targetUrl, capturedJwt));

    const raw = {
        nmap:       nmap.output,
        nuclei:     nuclei.output,
        ffuf:       ffuf.output,
        sqlmap:     sqlmap.output,
        jwt:        jwtReport,
        nucleiAuth: nucleiAuth.output,
        apiScan:    apiScan.output,
        metasploit: metasploit.output,
    };

    const combined = Object.entries(raw).map(([tool, output]) =>
        `===== ${tool.toUpperCase()} OUTPUT =====\n${output.trim()}`
    ).join('\n\n');

    // Save full recon log to disk
    try {
        const ts      = Date.now();
        const logFile = path.join(LOGS_DIR, `recon_${sessionId}_${ts}.txt`);
        fs.writeFileSync(logFile, combined, 'utf8');
        console.log(`[RECON] Log saved: ${logFile}`);
    } catch (e) {
        console.warn('[RECON] Failed to save log:', e.message);
    }

    const openPorts = (nmap.output.match(/\d+\/tcp\s+open/g) || []).length;
    console.log(`\n[RECON] Done — ${openPorts} open port(s) detected\n`);

    return { combined, raw, openPorts };
}

module.exports = { runAllRecon, safeRunTool, cleanForAnalysis, runMetasploit };
