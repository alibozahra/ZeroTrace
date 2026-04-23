'use strict';

// ============================================================
// NMAP — network port and service scanner
// ============================================================

const { execTool, cleanNmapOutput, parseTarget } = require('./utils');

function runNmap(target, scanType) {
    const { host, port } = parseTarget(target);
    let portFlag;
    if (scanType === 'full') {
        portFlag = '-p 1-65535';
    } else if (port) {
        const common = [80, 443, 8080, 8443, 8888, 22, 21, 25, 3306, 5432, 27017, 6379];
        const ports  = [...new Set([parseInt(port), ...common])].sort(function(a, b) { return a - b; }).join(',');
        portFlag = `-p ${ports}`;
    } else {
        portFlag = '-p 80,443,3000,8080,8443,8888,22,21,25,3306,5432,27017,6379';
    }
    const flags        = scanType === 'stealth' ? '-sS -sV -sC' : '-sV -sC -A';
    const extraScripts = scanType === 'stealth' ? '' : ' --script http-headers,http-cors,ssl-enum-ciphers,http-methods';
    return execTool(`nmap ${flags}${extraScripts} ${portFlag} ${host}`, 300000);
}

// Format nmap output into the === Section === format for the analysis model
function nmapSection(nmapOutput) {
    if (!nmapOutput || nmapOutput.length < 10) return null;
    const isHttp = nmapOutput.includes('HTTP') || nmapOutput.includes('html') || nmapOutput.includes('ppp?');
    const portLines = [];
    nmapOutput.split('\n').forEach(function(l) {
        const m = l.match(/(\d+)\/tcp\s+open\s+(.+)/);
        if (!m) return;
        let svcPart = m[2].trim();
        if ((svcPart.startsWith('ppp?') || svcPart === 'unknown') && isHttp) {
            svcPart = 'HTTP    web application';
        }
        portLines.push(m[1] + '/tcp   open  ' + svcPart);
    });
    if (portLines.length === 0) return null;
    const osLine = (nmapOutput.match(/OS details:\s*(.+)/) || [])[1] || '';
    let body = 'PORT     STATE SERVICE VERSION\n' + portLines.join('\n');
    if (osLine) body += '\nOS details: ' + osLine;
    return '=== Nmap Results ===\n' + body;
}

module.exports = { runNmap, nmapSection, cleanNmapOutput };
