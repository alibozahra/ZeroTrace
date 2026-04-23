'use strict';

// ============================================================
// VULNERABILITY ANALYZER — zerotrace-v2 analysis pipeline
// ============================================================

const { callOllama, unloadModel, MODELS } = require('../ai');
const { cleanForAnalysis }                = require('../recon/runner');
const { nucleiSection }                   = require('../recon/nuclei');
const { nmapSection }                     = require('../recon/nmap');
const { ffufSection }                     = require('../recon/ffuf');
const { sqlmapSection, sqlmapToDirectVulns } = require('../recon/sqlmap');
const { jwtSection, jwtToDirectVulns }    = require('../recon/jwt');
const { nucleiToDirectVulns }             = require('../recon/nuclei');
const { CVE_MAP, CVE_ENRICH }             = require('./cveMap');

const ZEROTRACE_SYSTEM =
`You are a vulnerability analysis AI. You will be given penetration testing tool outputs that have ALREADY been collected. Your ONLY job is to analyze these results and output a JSON list of vulnerabilities found.

DO NOT generate new commands. DO NOT suggest what to scan. DO NOT output markdown. DO NOT explain anything.

You must output ONLY this JSON and nothing else:
{
  "task": "analysis",
  "vulnerabilities": [
    {
      "name": "vulnerability name",
      "severity": "Critical|High|Medium|Low",
      "cve": "CVE-XXXX-XXXXX or null",
      "tool_detected_by": "tool name",
      "description": "one sentence description",
      "affected_component": "affected service or endpoint"
    }
  ]
}

If no vulnerabilities exist output: {"task": "analysis", "vulnerabilities": []}

IMPORTANT: Output JSON only. First character of your response must be {`;

function buildAnalysisPrompt(sectionContent) {
    return (
        'The following are ALREADY COLLECTED penetration testing tool results. ' +
        'Analyze them and identify all vulnerabilities:\n\n' +
        '--- TOOL RESULTS START ---\n' +
        sectionContent +
        '\n--- TOOL RESULTS END ---\n\n' +
        'Output your JSON analysis now:'
    );
}

function extractJSON(text) {
    if (!text) return null;
    try { return JSON.parse(text); } catch (_) {}
    const jsonMatch = text.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
    if (jsonMatch) { try { return JSON.parse(jsonMatch[1]); } catch (_) {} }
    const start = text.indexOf('{');
    const end   = text.lastIndexOf('}');
    if (start !== -1 && end !== -1 && end > start) { try { return JSON.parse(text.slice(start, end + 1)); } catch (_) {} }
    const aStart = text.indexOf('[');
    const aEnd   = text.lastIndexOf(']');
    if (aStart !== -1 && aEnd !== -1 && aEnd > aStart) { try { return JSON.parse(text.slice(aStart, aEnd + 1)); } catch (_) {} }
    let raw = '';
    if (start !== -1) {
        raw = text.slice(start);
        const oOpens  = (raw.match(/\{/g) || []).length;
        const oCloses = (raw.match(/\}/g) || []).length;
        const aOpens  = (raw.match(/\[/g) || []).length;
        const aCloses = (raw.match(/\]/g) || []).length;
        for (let i = 0; i < oOpens - oCloses; i++) raw += '}';
        for (let i = 0; i < aOpens  - aCloses; i++) raw += ']';
        try { return JSON.parse(raw); } catch (_) {}
    }
    return null;
}

const MAX_SECTION_CHARS = 6000;

// Fix B: accept target parameter
async function analyzeVulnerabilities(raw, target) {
    const targetUrl = target || 'N/A';
    const cleaned = cleanForAnalysis(raw);

    console.log('\n════════════════════════════════════════');
    console.log('STEP 2 — VULNERABILITY ANALYSIS (zerotrace-v2:latest)');
    console.log('════════════════════════════════════════');

    // Direct conversion — guaranteed vulns from nuclei/API scanner
    const directVulns = [
        ...nucleiToDirectVulns(cleaned.nuclei     || ''),
        ...nucleiToDirectVulns(cleaned.nucleiAuth || ''),
        ...nucleiToDirectVulns(cleaned.apiScan    || ''),
    ];
    console.log(`[ANALYSIS] Direct nuclei/API vulns: ${directVulns.length}`);

    const toolSections = [
        nmapSection(cleaned.nmap),
        ffufSection(cleaned.ffuf),
        jwtSection(cleaned.jwt),
        sqlmapSection(cleaned.sqlmap),
        nucleiSection(cleaned.apiScan),
    ].filter(Boolean);

    const allVulns = [...directVulns];

    const SECTION_TOOL_MAP = { nmap: 'nmap', ffuf: 'ffuf', jwt: 'jwt-tool', sqlmap: 'sqlmap', nuclei: 'nuclei', api: 'api-scanner' };

    // Fix D: fallback extractors for jwt and sqlmap
    const SECTION_FALLBACK_MAP = {
        'jwt':    function() { return jwtToDirectVulns(cleaned.jwt    || '', targetUrl); },
        'sqlmap': function() { return sqlmapToDirectVulns(cleaned.sqlmap || '', targetUrl); },
    };

    if (toolSections.length === 0) {
        console.warn('[ANALYSIS] No model-input sections — using direct vulns only');
    } else {
        for (var si = 0; si < toolSections.length; si++) {
            var section = toolSections[si];
            if (section.length > MAX_SECTION_CHARS) {
                section = section.substring(0, MAX_SECTION_CHARS) + '\n[...truncated for model context limit]';
            }
            var toolLabel = section.split('\n')[0].trim();
            var toolKey   = Object.keys(SECTION_TOOL_MAP).find(function(k) { return toolLabel.toLowerCase().includes(k); }) || 'zerotrace-v2';
            var toolName  = SECTION_TOOL_MAP[toolKey] || toolKey;
            console.log(`[ANALYSIS] ── ${toolLabel}`);

            // Fix C: per-section model reload
            try {
                await unloadModel(MODELS.analysis);
                await callOllama(MODELS.analysis, 'ping', { num_predict: 1 });
                console.log(`[ANALYSIS] ↺ Model reloaded for ${toolLabel}`);
            } catch (reloadErr) {
                console.warn(`[ANALYSIS] Reload failed for ${toolLabel}:`, reloadErr.message);
            }

            var prompt = buildAnalysisPrompt(section);
            var response = null;
            try {
                // Fix E: num_predict 2048 → 512
                response = await callOllama(
                    MODELS.analysis,
                    prompt,
                    { num_predict: 512, temperature: 0.1, stop: [] },
                    ZEROTRACE_SYSTEM
                );
                console.log(`[ANALYSIS] response_len=${response.length} : ${response.substring(0, 200)}`);
            } catch (err) {
                console.error(`[ANALYSIS] ✗ ${toolLabel} call failed:`, err.message);
                await new Promise(function(r) { setTimeout(r, 3000); });
                try {
                    response = await callOllama(
                        MODELS.analysis,
                        'Output only valid JSON.\n\n' + prompt,
                        { num_predict: 512, temperature: 0, stop: [] },
                        ZEROTRACE_SYSTEM
                    );
                } catch (retryErr) {
                    console.error(`[ANALYSIS] ✗ ${toolLabel} retry also failed:`, retryErr.message);
                    // Fix D: apply fallback extractor
                    var fallbackKey = Object.keys(SECTION_FALLBACK_MAP)
                        .find(function(k) { return toolLabel.toLowerCase().includes(k); });
                    if (fallbackKey) {
                        var fb = SECTION_FALLBACK_MAP[fallbackKey]();
                        if (fb.length) {
                            console.log(`[ANALYSIS] ↩ ${toolLabel} — fallback extractor: ${fb.length} finding(s)`);
                            allVulns.push(...fb);
                        }
                    }
                    if (si < toolSections.length - 1) {
                        await new Promise(function(r) { setTimeout(r, 3000); });
                    }
                    continue;
                }
            }

            var parsed = response ? extractJSON(response) : null;

            // Retry once with temperature=0 if JSON parse failed
            if (!parsed || (!Array.isArray(parsed.vulnerabilities) && !Array.isArray(parsed))) {
                console.warn(`[ANALYSIS] ${toolLabel} — no valid JSON, retrying…`);
                try {
                    response = await callOllama(
                        MODELS.analysis,
                        'Output only valid JSON.\n\n' + prompt,
                        { num_predict: 512, temperature: 0, stop: [] },
                        ZEROTRACE_SYSTEM
                    );
                    parsed = response ? extractJSON(response) : null;
                } catch (retryErr) {
                    console.error(`[ANALYSIS] ✗ ${toolLabel} retry failed:`, retryErr.message);
                    // Fix D: apply fallback extractor on JSON retry failure too
                    var fbKey2 = Object.keys(SECTION_FALLBACK_MAP)
                        .find(function(k) { return toolLabel.toLowerCase().includes(k); });
                    if (fbKey2) {
                        var fb2 = SECTION_FALLBACK_MAP[fbKey2]();
                        if (fb2.length) {
                            console.log(`[ANALYSIS] ↩ ${toolLabel} — fallback extractor: ${fb2.length} finding(s)`);
                            allVulns.push(...fb2);
                        }
                    }
                }
            }

            var parsedArray = null;
            if (parsed && !Array.isArray(parsed) && Array.isArray(parsed.vulnerabilities)) {
                console.log(`[ANALYSIS] ✓ ${toolLabel}: ${parsed.vulnerabilities.length} finding(s)`);
                parsedArray = parsed.vulnerabilities;
            } else if (Array.isArray(parsed) && parsed.length > 0) {
                console.log(`[ANALYSIS] ✓ ${toolLabel}: ${parsed.length} finding(s) (bare array)`);
                parsedArray = parsed;
            } else {
                console.warn(`[ANALYSIS] ✗ No valid JSON from ${toolLabel} — skipping`);
                // Fix D: fallback if still no parsedArray
                var fbKey3 = Object.keys(SECTION_FALLBACK_MAP)
                    .find(function(k) { return toolLabel.toLowerCase().includes(k); });
                if (fbKey3) {
                    var fb3 = SECTION_FALLBACK_MAP[fbKey3]();
                    if (fb3.length) {
                        console.log(`[ANALYSIS] ↩ ${toolLabel} — fallback extractor: ${fb3.length} finding(s)`);
                        allVulns.push(...fb3);
                    }
                }
            }

            if (parsedArray) {
                parsedArray.forEach(function(v) { if (!v.tool_detected_by) v.tool_detected_by = toolName; });
                allVulns.push(...parsedArray);
            }

            if (si < toolSections.length - 1) {
                await new Promise(function(r) { setTimeout(r, 3000); });
            }
        }
    }

    if (allVulns.length > 0) {
        // Deduplicate by name + affected_component
        var seenKeys = new Set();
        var deduped = allVulns.filter(function(v) {
            var key = (v.name || '').toLowerCase().replace(/\s+/g, ' ').trim()
                    + '|' + (v.affected_component || '').toLowerCase().trim();
            if (seenKeys.has(key)) return false;
            seenKeys.add(key);
            return true;
        });

        // Enrichment pass
        deduped.forEach(function(v) {
            if (!v.cve || v.cve === 'N/A') {
                const nameKey = (v.name || '').toLowerCase();
                for (var pattern in CVE_ENRICH) {
                    if (nameKey.includes(pattern) && CVE_ENRICH[pattern]) { v.cve = CVE_ENRICH[pattern]; break; }
                }
            }
            const meta = CVE_MAP[(v.name || '').toLowerCase()];
            if (meta) {
                if ((!v.cve || v.cve === 'N/A') && meta.cve) v.cve = meta.cve;
                if (!v.mitre && meta.mitre) v.mitre = meta.mitre;
            }
            if (!v.cve) v.cve = 'N/A';
        });

        console.log(`[ANALYSIS] Total: ${deduped.length} unique vulnerabilities`);
        return deduped;
    }

    // Fallback: nmap port-based findings
    console.warn('[ANALYSIS] Model analysis empty — falling back to nmap port list');
    const SERVICE_SEVERITY = {
        'ftp': 'High', 'telnet': 'Critical', 'smtp': 'Medium',
        'mysql': 'High', 'postgresql': 'High', 'mongodb': 'Critical',
        'redis': 'Critical', 'smb': 'High', 'rdp': 'High',
        'http': 'Medium', 'https': 'Low', 'ssh': 'Low'
    };
    const nmapOutput = cleaned.nmap;
    const portMatches = (nmapOutput.match(/(\d+)\/tcp\s+open\s+(\S+)/g) || []);
    if (portMatches.length > 0) {
        const vulns = portMatches.map(function(line) {
            const m = line.match(/(\d+)\/tcp\s+open\s+(\S+)/);
            const svc = (m[2] || '').toLowerCase();
            const sev = SERVICE_SEVERITY[svc] || 'Medium';
            return {
                name:               'Open Port ' + m[1] + ' (' + m[2] + ')',
                severity:           sev,
                cve:                'N/A',
                tool_detected_by:   'nmap',
                description:        'Port ' + m[1] + ' is open running ' + m[2] + '. Exposed services increase attack surface.',
                affected_component: m[2] + ':' + m[1]
            };
        });
        console.log(`[ANALYSIS] Fallback: ${vulns.length} port-based findings`);
        return vulns;
    }

    return [{
        name:               'Service Analysis Required',
        severity:           'Medium',
        cve:                'N/A',
        tool_detected_by:   'zerotrace-v2',
        description:        'Automated vulnerability extraction was inconclusive. Manual review recommended.',
        affected_component: 'Target system'
    }];
}

module.exports = { analyzeVulnerabilities, ZEROTRACE_SYSTEM, buildAnalysisPrompt, extractJSON };
