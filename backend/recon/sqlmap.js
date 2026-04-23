'use strict';

// ============================================================
// SQLMAP — SQL injection scanner
// ============================================================

const path = require('path');
const fs   = require('fs');
const { PYTHON, execTool } = require('./utils');

async function runSQLMap(target, ffufOutput) {
    const results = [];
    const sqlmapScript = path.join(__dirname, '../sqlmap_wrapper.py');
    const sqlmapCmd = fs.existsSync(sqlmapScript) ? `"${sqlmapScript}"` : 'C:\\tools\\sqlmap\\sqlmap.py';

    // Build endpoint list from ffuf output + known parameterized paths
    const endpoints = [];
    if (ffufOutput && !ffufOutput.startsWith('Error:') && !ffufOutput.includes('not recognized')) {
        for (const line of ffufOutput.split('\n')) {
            const trimmed = line.trim().replace(/\s*\[Status:[^\]]*\]/i, '').trim();
            if (trimmed && trimmed.length < 100 && !trimmed.startsWith('FFuf') &&
                (trimmed.includes('api') || trimmed.includes('rest') || trimmed.includes('login') || trimmed.includes('search'))) {
                const cleanPath = trimmed.startsWith('/') ? trimmed : '/' + trimmed;
                if (!cleanPath.includes('?')) {
                    endpoints.push(`${target}${cleanPath}?id=1`);
                } else {
                    endpoints.push(`${target}${cleanPath}`);
                }
            }
        }
    }
    endpoints.push(
        `${target}/rest/products/search?q=test`,
        `${target}/search?q=test`,
        `${target}/api/users?id=1`,
        `${target}/api/search?q=test`,
        `${target}/login?username=test`
    );

    for (const endpoint of endpoints.slice(0, 5)) {
        console.log(`[ZeroTrace] │  SQLMap testing: ${endpoint}`);
        const sslFlags = endpoint.startsWith('https://') ? ' --force-ssl --ignore-code 301' : '';
        const cmd = `${PYTHON} ${sqlmapCmd} -u "${endpoint}" --batch --level=2 --risk=1 --timeout=30 --random-agent --retries=2 --flush-session${sslFlags} 2>&1`;
        const output = await execTool(cmd, 180000);
        if (output && !output.includes('Usage:') && output.length > 100) {
            results.push(`${endpoint}: ${output.substring(0, 2000)}`);
            if (output.includes('injectable')) break;
        }
    }
    return results.join('\n\n') || 'SQLMap: No SQL injection found on tested endpoints.';
}

function sqlmapSection(sqlmapOutput) {
    if (!sqlmapOutput) return null;
    const lines = [];
    sqlmapOutput.split('\n').forEach(function(l) {
        const im = l.match(/Parameter\s+['"]?(\w+)['"]?\s+is\s+vulnerable/i)
                || l.match(/GET parameter\s+'(\w+)' appears to be/i)
                || l.match(/(\w+) parameter.*?injectable/i);
        if (!im) return;
        let type = 'SQL injection';
        if (/union/i.test(l))      type = 'UNION query injection';
        else if (/error/i.test(l)) type = 'error-based injection';
        else if (/blind/i.test(l)) type = 'time-based blind injection';
        lines.push('[+] Parameter \'' + im[1] + '\' is vulnerable to ' + type);
    });
    if (lines.length === 0) return null;
    return '=== SQLMap Results ===\n' + lines.join('\n');
}

function sqlmapToDirectVulns(rawSqlmapOutput, targetUrl) {
    if (!rawSqlmapOutput || rawSqlmapOutput.length < 10) return [];
    const url = targetUrl || 'target';
    const vulns = [], seen = new Set();
    for (const line of rawSqlmapOutput.split('\n')) {
        const m = line.match(/Parameter\s+['"]?(\w+)['"]?\s+is\s+vulnerable/i)
               || line.match(/GET parameter\s+'(\w+)' appears to be/i)
               || line.match(/(\w+) parameter.*?injectable/i);
        if (!m || seen.has(m[1])) continue;
        seen.add(m[1]);
        const isBlind = /blind/i.test(line), isUnion = /union/i.test(line);
        const typeStr = isUnion ? ' (UNION-based)' : isBlind ? ' (time-based blind)' : '';
        vulns.push({
            name:               'SQL Injection',
            severity:           isBlind ? 'High' : 'Critical',
            cve:                'CWE-89',
            mitre:              'T1190',
            tool_detected_by:   'sqlmap',
            description:        `SQLMap confirmed SQL injection${typeStr} on parameter '${m[1]}' at ${url}.`,
            affected_component: `${url}?${m[1]}=`
        });
    }
    return vulns;
}

module.exports = { runSQLMap, sqlmapSection, sqlmapToDirectVulns };
