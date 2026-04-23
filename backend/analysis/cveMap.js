'use strict';

// ============================================================
// CVE / CWE / MITRE LOOKUP TABLES
// Used by nuclei.js, apiScanner.js, and analyzer.js
// ============================================================

// Exact-match lookup by lowercase vuln name → { cve, mitre }
const CVE_MAP = {
    'content-security-policy missing':             { cve: '',              mitre: 'T1055' },
    'x-frame-options missing':                     { cve: '',              mitre: 'T1185' },
    'x-content-type-options missing':              { cve: '',              mitre: 'T1055' },
    'strict-transport-security (hsts) missing':    { cve: '',              mitre: 'T1557' },
    'strict-transport-security missing':           { cve: '',              mitre: 'T1557' },
    'referrer-policy missing':                     { cve: '',              mitre: 'T1055' },
    'permissions-policy missing':                  { cve: '',              mitre: 'T1055' },
    'cross-origin-opener-policy missing':          { cve: '',              mitre: 'T1185' },
    'cross-origin-resource-policy missing':        { cve: '',              mitre: 'T1185' },
    'cross-origin-embedder-policy missing':        { cve: '',              mitre: 'T1185' },
    'x-permitted-cross-domain-policies missing':   { cve: '',              mitre: 'T1185' },
    'clear-site-data missing':                     { cve: '',              mitre: 'T1055' },
    'prometheus metrics exposed':                  { cve: '',              mitre: 'T1082' },
    'prometheus metrics':                          { cve: '',              mitre: 'T1082' },
    'swagger api documentation exposed':           { cve: '',              mitre: 'T1082' },
    'public swagger api':                          { cve: '',              mitre: 'T1082' },
    'swagger json exposed':                        { cve: '',              mitre: 'T1082' },
    'ftp directory listing exposed':               { cve: 'CVE-1999-0497', mitre: 'T1083' },
    'encryption keys directory exposed':           { cve: '',              mitre: 'T1552' },
    'git repository exposed':                      { cve: '',              mitre: 'T1083' },
    'php info page exposed':                       { cve: '',              mitre: 'T1082' },
    'apache server status exposed':                { cve: '',              mitre: 'T1082' },
    'spring boot actuator environment exposed':    { cve: '',              mitre: 'T1082' },
    'cors misconfiguration':                       { cve: 'CWE-942',       mitre: 'T1185' },
    'cors wildcard':                               { cve: 'CWE-942',       mitre: 'T1185' },
    'dangerous http methods allowed':              { cve: '',              mitre: 'T1190' },
    'weak jwt secret key (hs256)':                 { cve: 'CWE-347',       mitre: 'T1552' },
    'jwt authentication present':                  { cve: 'CWE-347',       mitre: 'T1552' },
    'jwt algorithm none accepted':                 { cve: 'CVE-2015-9235', mitre: 'T1552' },
    'jwt algorithm confusion (rs256→hs256)':       { cve: 'CVE-2022-21449', mitre: 'T1552' },
    'sql injection':                               { cve: 'CWE-89',        mitre: 'T1190' },
    'server version disclosure':                   { cve: '',              mitre: 'T1082' },
    'technology disclosure':                       { cve: '',              mitre: 'T1082' },
    'idor':                                        { cve: 'CWE-284',       mitre: 'T1078' },
    'http missing security headers: content-security-policy':           { cve: '', mitre: 'T1055' },
    'http missing security headers: x-frame-options':                   { cve: '', mitre: 'T1185' },
    'http missing security headers: strict-transport-security':         { cve: '', mitre: 'T1557' },
    'http missing security headers: referrer-policy':                   { cve: '', mitre: 'T1055' },
    'http missing security headers: permissions-policy':                { cve: '', mitre: 'T1055' },
    'http missing security headers: cross-origin-opener-policy':        { cve: '', mitre: 'T1185' },
    'http missing security headers: cross-origin-resource-policy':      { cve: '', mitre: 'T1185' },
    'http missing security headers: cross-origin-embedder-policy':      { cve: '', mitre: 'T1185' },
    'http missing security headers: x-permitted-cross-domain-policies': { cve: '', mitre: 'T1185' },
    'http missing security headers: clear-site-data':                   { cve: '', mitre: 'T1055' },
    'http missing security headers: missing-content-type':              { cve: '', mitre: 'T1055' },
};

// Substring-match enrichment for model-generated vulns that may have variant naming
const CVE_ENRICH = {
    'ftp anonymous':        'CVE-1999-0497',
    'vsftpd 2.3.4':         'CVE-2011-2523',
    'smb':                  'CVE-2017-0144',
    'redis':                'CVE-2022-0543',
    'telnet':               'CVE-1999-0619',
    'sql injection':        'CWE-89',
    'xss':                  'CWE-79',
    'cross-site scripting': 'CWE-79',
    'idor':                 'CWE-284',
    'cors':                 'CWE-942',
    'jwt':                  'CWE-347',
    'path traversal':       'CVE-2021-41773',
    'directory traversal':  'CVE-2021-41773',
    'open redirect':        'CWE-601',
    'xxe':                  'CWE-611',
    'ssrf':                 'CWE-918',
    'command injection':    'CWE-78',
    'deserialization':      'CWE-502',
    'clickjacking':         'CWE-1021',
};

module.exports = { CVE_MAP, CVE_ENRICH };
