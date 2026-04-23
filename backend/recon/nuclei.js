'use strict';

// ============================================================
// NUCLEI — CVE and misconfiguration scanner
// ============================================================

const path = require('path');
const fs   = require('fs');
const { execTool, cleanNucleiOutput } = require('./utils');
const { CVE_MAP } = require('../analysis/cveMap');

let cachedNucleiPath = null; // set on first run, reused by runNucleiAuthenticated

const LOGS_DIR = path.join(__dirname, '../../logs');

async function runNuclei(target) {
    const nucleiPaths = [
        'nuclei',
        'C:\\tools\\nuclei\\nuclei.exe',
        'C:\\Program Files\\nuclei\\nuclei.exe',
        path.join(process.env.USERPROFILE || '', 'go', 'bin', 'nuclei.exe'),
        path.join(process.env.USERPROFILE || '', 'AppData', 'Local', 'nuclei', 'nuclei.exe'),
    ];

    let nucleiPath = null;
    for (const np of nucleiPaths) {
        const probe = await execTool(`"${np}" -version 2>&1`, 10000).catch(function() { return 'Error:'; });
        if (probe && !probe.includes('not recognized') && !probe.includes('cannot find the path') &&
            !probe.includes('is not recognized') && !probe.startsWith('Error:')) {
            nucleiPath = np;
            break;
        }
    }
    if (!nucleiPath) {
        console.warn('[ZeroTrace] │  Nuclei not found in any known path — skipping');
        return 'Nuclei: not installed or not found in PATH.';
    }
    console.log(`[ZeroTrace] │  Nuclei found at: ${nucleiPath}`);
    cachedNucleiPath = nucleiPath;

    // Update templates once per day
    const flagFile  = path.join(LOGS_DIR, '.nuclei_updated');
    const today     = new Date().toISOString().slice(0, 10);
    let needsUpdate = true;
    try { needsUpdate = fs.readFileSync(flagFile, 'utf8').trim() !== today; } catch (_) {}
    if (needsUpdate) {
        console.log('[ZeroTrace] │  Updating nuclei templates...');
        await execTool(`"${nucleiPath}" -update-templates -nc 2>&1`, 120000).catch(function() {});
        try { fs.writeFileSync(flagFile, today, 'utf8'); } catch (_) {}
        console.log('[ZeroTrace] │  Nuclei templates updated');
    }

    const cmd    = `"${nucleiPath}" -u "${target}" -tags cve,owasp,exposure,misconfig,auth,sqli,xss,ssrf,rce,lfi,redirect,default-login,tech,takeover -severity info,low,medium,high,critical -timeout 5 -rl 150 -c 40 -nc -j 2>&1`;
    const output = await execTool(cmd, 1800000); // 30 min cap
    return cleanNucleiOutput(output);
}

async function runNucleiAuthenticated(target, jwtToken) {
    if (!jwtToken || !cachedNucleiPath) {
        const reason = !jwtToken ? 'no JWT token captured' : 'nuclei binary not found';
        console.log(`[ZeroTrace] │  Nuclei (authenticated): skipped — ${reason}`);
        return `Nuclei (authenticated): skipped — ${reason}.`;
    }
    console.log('[ZeroTrace] │  Nuclei authenticated pass with captured JWT');
    const cmd    = `"${cachedNucleiPath}" -u "${target}" -H "Authorization: Bearer ${jwtToken}" -tags idor,auth,owasp,exposure,misconfig,sqli,xss,ssrf,rce,lfi -severity low,medium,high,critical -timeout 15 -rl 100 -c 30 -nc -j 2>&1`;
    const output = await execTool(cmd, 1800000);
    const cleaned = cleanNucleiOutput(output);
    if (cleaned.startsWith('Nuclei: scan completed')) return 'Nuclei (authenticated): no additional findings.';
    return 'Nuclei (authenticated) findings:\n' + cleaned;
}

// Format nuclei output for the analysis model
function nucleiSection(nucleiOutput) {
    if (!nucleiOutput || nucleiOutput.includes('no findings') || nucleiOutput.includes('no vulnerabilities') ||
        nucleiOutput.includes('skipped') || nucleiOutput.includes('no additional findings')) return null;
    const lines = [];
    nucleiOutput.split('\n').forEach(function(l) {
        const m = l.match(/^\[(INFO|LOW|MEDIUM|HIGH|CRITICAL)\]\s+(.+?)\s+(?:—|--?|–)\s+(https?:\/\/\S+)/i);
        if (m) {
            const sev  = m[1].toLowerCase();
            const name = m[2].replace(/\s*-\s*(Detect|Detection|Exposure)$/i, '').trim();
            const tid  = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '');
            lines.push('[' + sev + '] [' + tid + '] [http] ' + m[3] + ' — ' + name);
        } else {
            const m2 = l.match(/^\[(INFO|LOW|MEDIUM|HIGH|CRITICAL)\]\s+(.+)/i);
            if (m2) lines.push('[' + m2[1].toLowerCase() + '] ' + m2[2].trim());
        }
    });
    if (lines.length === 0) return null;
    return '=== Nuclei Results ===\n' + lines.join('\n');
}

// Convert nuclei/API scanner output directly to vuln objects — no model needed.
// Guarantees categorical findings (missing headers, exposed endpoints) always appear.
function nucleiToDirectVulns(output) {
    if (!output || output.includes('no findings') || output.includes('skipped') || output.includes('no additional')) return [];
    const vulns = [];
    const SEV   = { info: 'Low', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
    for (const line of output.split('\n')) {
        const m = line.match(/^\[(INFO|LOW|MEDIUM|HIGH|CRITICAL)\]\s+(.+?)\s+(?:—|--?|–)\s+(https?:\/\/\S+)/i);
        if (!m) continue;
        const sev  = SEV[m[1].toLowerCase()] || 'Low';
        const name = m[2].replace(/\s*-\s*(Detect|Detection|Exposure)$/i, '').trim();
        const url  = m[3];
        if (/FingerprintHub|Add DOM EventListener|OWASP Juice Shop$/i.test(name)) continue;
        const meta = CVE_MAP[name.toLowerCase()] || { cve: '', mitre: '' };
        vulns.push({
            name,
            severity:           sev,
            cve:                meta.cve || 'N/A',
            mitre:              meta.mitre,
            tool_detected_by:   'nuclei',
            description:        `Nuclei confirmed: ${name} detected at ${url}`,
            affected_component: url,
        });
    }
    return vulns;
}

module.exports = { runNuclei, runNucleiAuthenticated, nucleiSection, nucleiToDirectVulns, cleanNucleiOutput };
