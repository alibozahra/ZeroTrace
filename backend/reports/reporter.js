'use strict';

// ============================================================
// REPORT BUILDER — vuln report, exploit report, PDF generation
// ============================================================

const path = require('path');
const fs   = require('fs');
const PDFDocument = require('pdfkit');

const { callMistral, unloadModel, MODELS } = require('../ai');
const { REPORTS_DIR }                      = require('../sessions');
const { searchMetasploitModules, mapMitre, extractJSON } = require('../exploits/exploiter');

// ============================================================
// HELPERS
// ============================================================

function severityToImpact(severity) {
    const map = { Critical: 'Very High', High: 'High', Medium: 'Medium', Low: 'Low' };
    return map[severity] || 'Unknown';
}

function severityToLikelihood(severity) {
    const map = { Critical: 'High', High: 'Medium-High', Medium: 'Medium', Low: 'Low' };
    return map[severity] || 'Unknown';
}

function truncateComponent(comp) {
    if (!comp || comp === 'N/A') return 'N/A';
    try { const p = new URL(comp).pathname; return p && p !== '/' ? p : comp.substring(0, 45); }
    catch (_) { return comp.length > 45 ? comp.substring(0, 42) + '...' : comp; }
}

// Fix common Mistral prose spacing issues (missing spaces between words)
function fixProseSpacing(text) {
    if (!text) return '';
    return text
        // Add space between lowercase→uppercase transitions that are word boundaries
        .replace(/([a-z])([A-Z][a-z])/g, '$1 $2')
        // Add space after sentence-ending punctuation when next char is uppercase
        .replace(/([.!?])([A-Z])/g, '$1 $2')
        // Fix missing space after comma
        .replace(/,([a-zA-Z])/g, ', $1')
        // Fix missing space before opening parens when preceded by a letter
        .replace(/([a-zA-Z])\(/g, '$1 (')
        // Collapse multiple spaces
        .replace(/  +/g, ' ')
        .trim();
}

function cleanDescription(v) {
    if (!v.description || v.description.startsWith('Nuclei confirmed:') || v.description.startsWith('API Scanner')) {
        return 'The ' + v.name + ' issue was identified at ' + (v.affected_component || 'the target') +
               '. Exploitation of this vulnerability could lead to ' + severityToImpact(v.severity).toLowerCase() + '-impact attacks against the application.';
    }
    return v.description;
}

// ============================================================
// VULNERABILITY REPORT TEMPLATE
// ============================================================

function buildVulnReportTemplate(session, overallRisk, severityCounts, toolsUsed, vulns, execSummary, recommendationsText, conclusionText) {
    const target = session.target;
    const date   = new Date(session.createdAt).toLocaleDateString();
    const lines  = [];

    const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    const sorted = [...vulns].sort(function(a, b) {
        return (SEV_ORDER[a.severity] !== undefined ? SEV_ORDER[a.severity] : 4) -
               (SEV_ORDER[b.severity] !== undefined ? SEV_ORDER[b.severity] : 4);
    });

    lines.push('# ZeroTrace Vulnerability Analysis Report');
    lines.push('');
    lines.push('| Field | Value |');
    lines.push('|-------|-------|');
    lines.push('| **Target** | ' + target + ' |');
    lines.push('| **Date** | ' + date + ' |');
    lines.push('| **Classification** | CONFIDENTIAL |');
    lines.push('| **Tool** | ZeroTrace v1.0 |');
    lines.push('| **Overall Risk** | ' + overallRisk + ' |');
    lines.push('');

    const critHigh = severityCounts.Critical + severityCounts.High;
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(execSummary || ('A vulnerability assessment was conducted against **' + target + '** on ' + date + '. ' +
        vulns.length + ' vulnerabilities were identified with an overall risk rating of **' + overallRisk + '**. ' +
        (critHigh > 0 ? critHigh + ' critical/high severity findings require immediate attention.' : 'No critical findings were identified.') +
        ' Detailed findings and prioritized remediation guidance are provided below.'));
    lines.push('');

    lines.push('## Scope and Methodology');
    lines.push('');
    lines.push('**Target:** ' + target);
    lines.push('');
    lines.push('**Assessment Date:** ' + date);
    lines.push('');
    lines.push('**Tools Used:** ' + (toolsUsed.length ? toolsUsed.join(', ') : 'nmap, nuclei, ffuf, sqlmap, jwt-tool, api-scanner'));
    lines.push('');
    lines.push('**Coverage:** Network reconnaissance (nmap), CVE and misconfiguration scanning (nuclei), ' +
        'directory and API endpoint discovery (ffuf), SQL injection testing (sqlmap), JWT authentication analysis, ' +
        'REST API security testing (api-scanner), and auxiliary service scanning.');
    lines.push('');

    lines.push('## Risk Matrix');
    lines.push('');
    lines.push('| Severity | Count | Impact | Likelihood | Risk Level |');
    lines.push('|----------|-------|--------|------------|------------|');
    lines.push('| Critical | ' + severityCounts.Critical + ' | Very High | High | Critical |');
    lines.push('| High | ' + severityCounts.High + ' | High | Medium-High | High |');
    lines.push('| Medium | ' + severityCounts.Medium + ' | Medium | Medium | Medium |');
    lines.push('| Low | ' + severityCounts.Low + ' | Low | Low | Low |');
    lines.push('');

    lines.push('## Findings Summary');
    lines.push('');
    lines.push('| # | Vulnerability | Severity | CVE | Component | Detected By |');
    lines.push('|---|--------------|----------|-----|-----------|-------------|');
    sorted.forEach(function(v, i) {
        lines.push('| ' + (i+1) + ' | ' + v.name + ' | ' + v.severity + ' | ' + (v.cve || 'N/A') + ' | ' + truncateComponent(v.affected_component) + ' | ' + (v.tool_detected_by || 'N/A') + ' |');
    });
    lines.push('');
    lines.push('**Severity Breakdown:** Critical: ' + severityCounts.Critical + ', High: ' + severityCounts.High + ', Medium: ' + severityCounts.Medium + ', Low: ' + severityCounts.Low);
    lines.push('');

    lines.push('## Detailed Findings');
    lines.push('');
    sorted.forEach(function(v, i) {
        const mitreDisplay = v.mitre_technique || (v.mitre ? 'ATT&CK ' + v.mitre : null);
        lines.push('### ' + (i+1) + '. ' + v.name);
        lines.push('');
        lines.push('| Field | Value |');
        lines.push('|-------|-------|');
        lines.push('| **Severity** | ' + v.severity + ' |');
        lines.push('| **CVE / CWE** | ' + (v.cve || 'N/A') + ' |');
        lines.push('| **Component** | ' + (v.affected_component || 'N/A') + ' |');
        lines.push('| **Detected By** | ' + (v.tool_detected_by || 'N/A') + ' |');
        lines.push('| **Impact** | ' + severityToImpact(v.severity) + ' |');
        lines.push('| **Likelihood** | ' + severityToLikelihood(v.severity) + ' |');
        if (mitreDisplay) lines.push('| **MITRE ATT&CK** | ' + mitreDisplay + ' |');
        lines.push('');
        lines.push('**Description:**');
        lines.push(cleanDescription(v));
        lines.push('');
        lines.push('**Remediation:**');
        lines.push(v.remediation || 'Review and harden the affected component against this vulnerability class.');
        lines.push('');
        if (i < sorted.length - 1) lines.push('---');
        lines.push('');
    });

    lines.push('## Recommendations');
    lines.push('');
    if (recommendationsText && recommendationsText.trim().length > 20) {
        lines.push(recommendationsText.trim());
    } else {
        lines.push('Prioritized remediation steps:');
        ['Critical', 'High', 'Medium', 'Low'].forEach(function(p) {
            const pvulns = vulns.filter(function(v) { return v.severity === p; });
            if (pvulns.length) {
                lines.push('');
                lines.push('**' + p + ' Priority:**');
                pvulns.forEach(function(v) { lines.push('- Remediate ' + v.name + ' on ' + (v.affected_component || 'target')); });
            }
        });
    }
    lines.push('');

    lines.push('## Conclusion');
    lines.push('');
    if (conclusionText && conclusionText.trim().length > 20) {
        lines.push(conclusionText.trim());
    } else {
        lines.push('The assessment of ' + target + ' revealed ' + vulns.length + ' vulnerabilities. ' +
            (critHigh > 0 ? 'Immediate remediation of ' + critHigh + ' critical/high findings is strongly recommended before the next assessment cycle.' :
            'Addressing the identified findings will improve the overall security posture of the target.'));
    }
    lines.push('');
    lines.push('---');
    lines.push('*Generated by ZeroTrace v1.0 — AI-Powered Penetration Testing Platform.*');
    return lines.join('\n');
}

// ============================================================
// BUILD VULN REPORT  (Fix F: per-vuln Mistral, not batched)
// ============================================================

async function buildVulnReport(session) {
    const vulns = session.vulnerabilities || [];
    if (!vulns.length) throw new Error('No vulnerabilities to report.');

    const severityOrder  = ['Critical', 'High', 'Medium', 'Low'];
    let   overallRisk    = 'Low';
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    vulns.forEach(function(v) {
        const sev = v.severity || 'Low';
        if (Object.prototype.hasOwnProperty.call(severityCounts, sev)) severityCounts[sev]++;
        if (severityOrder.indexOf(sev) < severityOrder.indexOf(overallRisk)) overallRisk = sev;
    });
    const toolsUsed = [...new Set(vulns.map(function(v) { return v.tool_detected_by; }).filter(Boolean))];
    const enrichedVulns = vulns.map(function(v) {
        const ml = mapMitre(v.name);
        if (ml) v.mitre_technique = ml.tactic + ' :: ' + ml.name + ' (' + ml.technique + ')';
        return v;
    });

    console.log('\n[VULN REPORT] Generating vulnerability analysis report...');
    await unloadModel(MODELS.analysis);
    await new Promise(r => setTimeout(r, 3000));

    const target = session.target;
    const date   = new Date(session.createdAt).toLocaleDateString();

    // Executive summary
    const critHighCount = (severityCounts.Critical || 0) + (severityCounts.High || 0);
    const summaryPrompt = 'Write a 3-sentence professional executive summary for a vulnerability assessment of ' + target + ' on ' + date + '. ' +
        'Overall risk: ' + overallRisk + '. ' +
        'Finding counts: Critical=' + (severityCounts.Critical||0) + ', High=' + (severityCounts.High||0) + ', Medium=' + (severityCounts.Medium||0) + ', Low=' + (severityCounts.Low||0) + '. ' +
        'Summarize the overall security posture and the main risk themes. ' +
        'Do NOT list individual vulnerability names — they are detailed in the findings section. ' +
        'No headers, no bullet points, exactly 3 plain sentences.';

    let execSummary;
    try {
        execSummary = await callMistral([
            { role: 'system', content: 'You are a security report writer. Write concise, professional executive summaries in plain sentences.' },
            { role: 'user', content: summaryPrompt }
        ], { num_predict: 250, num_ctx: 4096, temperature: 0.3 });
        if (!execSummary || execSummary.length < 30) throw new Error('Summary too short');
        execSummary = fixProseSpacing(execSummary);
        console.log('[VULN REPORT] Mistral exec summary: ' + execSummary.length + ' chars');
    } catch (err) {
        console.warn('[VULN REPORT] Mistral summary failed, using default:', err.message);
        execSummary = 'A vulnerability assessment was conducted against ' + target + ' on ' + date + ', identifying ' + enrichedVulns.length + ' security finding(s) with an overall risk rating of ' + overallRisk + '. ' +
            'Critical findings include: ' + enrichedVulns.filter(function(v){ return v.severity === 'Critical' || v.severity === 'High'; }).map(function(v){ return v.name; }).join(', ') + '. ' +
            'Immediate remediation is recommended for all high and critical severity vulnerabilities.';
    }

    // Fix F: per-vulnerability Mistral calls (not batched)
    console.log('[VULN REPORT] Generating per-vulnerability sections via Mistral (per-vuln)...');
    for (var vi = 0; vi < enrichedVulns.length; vi++) {
        var v = enrichedVulns[vi];
        try {
            var prompt = 'Write a description and remediation for this penetration test finding.\n\n' +
                'Finding: ' + v.name + '\nSeverity: ' + v.severity +
                '\nComponent: ' + (v.affected_component || 'N/A') +
                (v.cve && v.cve !== 'N/A' ? '\nCVE: ' + v.cve : '') + '\n\n' +
                'Rules:\n- DESCRIPTION (2 sentences): explain WHY dangerous. No generic phrases.\n' +
                '- REMEDIATION (2 sentences): specific fix.\n\n' +
                'Format:\nDESCRIPTION: [text]\nREMEDIATION: [text]';
            var resp = await callMistral([
                { role: 'system', content: 'You are a cybersecurity expert writing a pentest report.' },
                { role: 'user', content: prompt }
            ], { num_predict: 320, num_ctx: 4096, temperature: 0.3 });
            var descM = resp.match(/DESCRIPTION:\s*([\s\S]+?)(?=REMEDIATION:|$)/i);
            var remM  = resp.match(/REMEDIATION:\s*([\s\S]+?)$/i);
            if (descM && descM[1].trim().length > 20) v.description = fixProseSpacing(descM[1].trim());
            if (remM  && remM[1].trim().length  > 20) v.remediation = fixProseSpacing(remM[1].trim());
            console.log('[VULN REPORT] [' + (vi+1) + '/' + enrichedVulns.length + '] ' + v.name);
        } catch (ve) {
            console.warn('[VULN REPORT] Mistral call ' + (vi+1) + ' failed:', ve.message);
        }
    }

    // Recommendations section
    let recommendationsText = null;
    try {
        const criticalCount = (severityCounts.Critical||0) + (severityCounts.High||0);
        recommendationsText = await callMistral([
            { role: 'system', content: 'You are a cybersecurity expert writing strategic remediation recommendations for a penetration test report.' },
            { role: 'user', content: 'Write 5 prioritized strategic recommendations for securing ' + target + '.\n\n' +
                'Context: ' + enrichedVulns.length + ' vulnerabilities found (' + criticalCount + ' critical/high). ' +
                'Tools flagged issues in: ' + [...new Set(enrichedVulns.map(function(v){ return v.tool_detected_by; }).filter(Boolean))].join(', ') + '.\n\n' +
                'Rules:\n' +
                '- Focus on STRATEGIC fixes (e.g. authentication hardening, input validation, patch management) — not individual vulnerability names.\n' +
                '- Each recommendation must address a different security domain.\n' +
                '- Do not repeat the per-finding remediations already documented in the report.\n' +
                '- Numbered list, most critical first. No headers.' }
        ], { num_predict: 400, num_ctx: 4096, temperature: 0.3 });
        console.log('[VULN REPORT] Mistral recommendations: ' + (recommendationsText||'').length + ' chars');
    } catch (re) {
        console.warn('[VULN REPORT] Mistral recommendations failed:', re.message);
    }

    // Conclusion
    let conclusionText = null;
    try {
        conclusionText = await callMistral([
            { role: 'system', content: 'You are a cybersecurity expert writing a penetration test report conclusion.' },
            { role: 'user', content: 'Write a 2-sentence conclusion for a vulnerability assessment of ' + target + '. ' +
                'The executive summary already stated the finding count and risk level — do NOT repeat them. ' +
                'Focus on: (1) what the findings reveal about the target\'s security maturity, and (2) the recommended next step (e.g. remediate and retest, implement SSDLC, etc.).' }
        ], { num_predict: 150, num_ctx: 4096, temperature: 0.3 });
        console.log('[VULN REPORT] Mistral conclusion: ' + (conclusionText||'').length + ' chars');
    } catch (ce) {
        console.warn('[VULN REPORT] Mistral conclusion failed:', ce.message);
    }

    const markdown = buildVulnReportTemplate(session, overallRisk, severityCounts, toolsUsed, enrichedVulns, execSummary, recommendationsText, conclusionText);

    const ts      = Date.now();
    const slug    = session.target.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 40);
    const mdFile  = path.join(REPORTS_DIR, 'vuln_' + slug + '_' + ts + '.md');
    const pdfFile = path.join(REPORTS_DIR, 'vuln_' + slug + '_' + ts + '.pdf');

    fs.writeFileSync(mdFile, markdown, 'utf8');
    await buildPdf(session.target, new Date(session.createdAt).toLocaleDateString(), markdown, pdfFile);
    return { markdown, mdFile, pdfFile, overallRisk };
}

// ============================================================
// EXPLOIT REPORT TEMPLATE
// ============================================================

function buildExploitReportTemplate(session, exploits, execSummary, conclusionText) {
    const target = session.target || 'Manual Input';
    const date   = new Date(session.createdAt).toLocaleDateString();
    const lines  = [];

    lines.push('# ZeroTrace Exploit Generation Report');
    lines.push('');
    lines.push('| Field | Value |');
    lines.push('|-------|-------|');
    lines.push('| **Target** | ' + target + ' |');
    lines.push('| **Date** | ' + date + ' |');
    lines.push('| **Classification** | CONFIDENTIAL |');
    lines.push('| **Tool** | ZeroTrace v1.0 |');
    lines.push('');

    lines.push('## Executive Summary');
    lines.push('');
    lines.push(execSummary || (exploits.length + ' proof-of-concept exploit(s) were generated for the identified vulnerabilities in this assessment. Immediate remediation is recommended for all critical and high severity findings.'));
    lines.push('');

    lines.push('## Exploits Overview');
    lines.push('');
    lines.push('| # | Vulnerability | MITRE ATT&CK | Complexity |');
    lines.push('|---|--------------|--------------|------------|');
    exploits.forEach(function(e, i) {
        lines.push('| ' + (i+1) + ' | ' + e.name + ' | ' + (e.mitre_technique || 'N/A') + ' | Medium |');
    });
    lines.push('');

    lines.push('## Detailed Exploits');
    lines.push('');
    exploits.forEach(function(e, i) {
        lines.push('### ' + (i+1) + '. ' + e.name);
        lines.push('');
        if (e.mitre_technique) lines.push('- **MITRE ATT&CK:** ' + e.mitre_technique);
        lines.push('');
        if (e.attack_narrative) {
            lines.push('**Attack Scenario:**');
            lines.push(e.attack_narrative);
            lines.push('');
        }
        if (e.exploitation_steps && e.exploitation_steps.length) {
            lines.push('**Exploitation Steps:**');
            e.exploitation_steps.forEach(function(s, si) {
                lines.push((si+1) + '. ' + s.replace(/^\d+\.\s*/, ''));
            });
            lines.push('');
        }
        if (e.exploit_code) {
            lines.push('**Proof of Concept:**');
            lines.push('```python');
            lines.push(e.exploit_code.substring(0, 2000));
            lines.push('```');
            lines.push('');
            lines.push('**How to Run:**');
            lines.push('1. Save the above code to a file, e.g. `exploit_' + (i+1) + '.py`');
            lines.push('2. Install dependencies: `pip install requests`');
            lines.push('3. Run: `python exploit_' + (i+1) + '.py`');
            lines.push('4. Review output for successful exploitation indicators.');
            lines.push('');
        }
        if (e.remediation) {
            lines.push('**Remediation:**');
            lines.push(e.remediation);
            lines.push('');
        }
    });

    lines.push('## Responsible Disclosure Notice');
    lines.push('');
    lines.push('The exploit code and techniques in this report are for authorized security testing only. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.');
    lines.push('');

    lines.push('## Conclusion');
    lines.push('');
    if (conclusionText && conclusionText.trim().length > 20) {
        lines.push(conclusionText.trim());
        lines.push('');
        lines.push(exploits.length + ' exploit(s) were generated. All findings must be used exclusively for authorized testing and remediation verification.');
    } else {
        lines.push(exploits.length + ' exploit(s) were generated. All findings must be used exclusively for authorized testing and remediation verification. Patch all identified vulnerabilities before re-testing.');
    }
    lines.push('');
    lines.push('---');
    lines.push('*Generated by ZeroTrace v1.0 — AI-Powered Penetration Testing Platform.*');
    return lines.join('\n');
}

async function buildExploitReport(session) {
    const exploits = session.exploits || [];
    if (!exploits.length) throw new Error('No exploits to report.');

    const target = session.target || 'Manual Input';
    const date   = new Date(session.createdAt).toLocaleDateString();

    console.log('\n[EXPLOIT REPORT] Generating exploit report...');
    await unloadModel(MODELS.exploits);
    await new Promise(r => setTimeout(r, 3000));

    const summaryItems = exploits.map(function(e) {
        return e.name + (e.mitre_technique && e.mitre_technique !== 'N/A' ? ' (' + e.mitre_technique + ')' : '');
    }).join('; ');
    const summaryPrompt = 'Write a 3-sentence professional executive summary for a penetration test of ' + target + ' on ' + date + '. ' +
        'Exploits developed: ' + summaryItems + '. ' +
        'Be concise and professional. No headers, no bullet points, just 3 plain sentences.';

    let execSummary;
    try {
        execSummary = await callMistral([
            { role: 'system', content: 'You are a security report writer. Write concise, professional executive summaries in plain sentences.' },
            { role: 'user', content: summaryPrompt }
        ], { num_predict: 250, num_ctx: 4096, temperature: 0.3 });
        if (!execSummary || execSummary.length < 30) throw new Error('Summary too short');
        console.log('[EXPLOIT REPORT] Mistral exec summary: ' + execSummary.length + ' chars');
    } catch (err) {
        console.warn('[EXPLOIT REPORT] Mistral summary failed, using default:', err.message);
        execSummary = 'A penetration test was conducted against ' + target + ' on ' + date + ', resulting in ' + exploits.length + ' proof-of-concept exploit(s) being developed for identified vulnerabilities. ' +
            'The assessment revealed ' + exploits.filter(function(e){ return e.mitre_technique && e.mitre_technique !== 'N/A'; }).length + ' MITRE ATT&CK mapped techniques applicable to the target environment. ' +
            'Immediate remediation is recommended for all critical and high severity findings prior to production deployment.';
    }

    // Per-exploit attack narrative via Mistral
    console.log('[EXPLOIT REPORT] Generating per-exploit narratives via Mistral...');
    for (var ei = 0; ei < exploits.length; ei++) {
        var e = exploits[ei];
        try {
            var exp_prompt = 'Write 2 short paragraphs for a penetration test exploit report.\n\n' +
                'Exploit: ' + e.name + '\n' +
                (e.mitre_technique && e.mitre_technique !== 'N/A' ? 'MITRE ATT&CK: ' + e.mitre_technique + '\n' : '') +
                '\nParagraph 1 — Attack Scenario (2-3 sentences): describe how an attacker would exploit this vulnerability in a real engagement, including the impact.\n' +
                'Paragraph 2 — Remediation (2-3 sentences): explain the specific steps needed to fix this vulnerability.\n\n' +
                'Format exactly as:\nATTACK: [your text]\nREMEDIATION: [your text]';
            var exp_resp = await callMistral([
                { role: 'system', content: 'You are a penetration tester writing an exploit development report. Be technical and professional.' },
                { role: 'user', content: exp_prompt }
            ], { num_predict: 320, num_ctx: 4096, temperature: 0.3 });
            var attackMatch = exp_resp.match(/ATTACK:\s*([\s\S]+?)(?=REMEDIATION:|$)/i);
            var remMatch2   = exp_resp.match(/REMEDIATION:\s*([\s\S]+?)$/i);
            if (attackMatch && attackMatch[1].trim().length > 20) e.attack_narrative = fixProseSpacing(attackMatch[1].trim());
            if (remMatch2   && remMatch2[1].trim().length   > 20) e.remediation = fixProseSpacing(remMatch2[1].trim());
            console.log('[EXPLOIT REPORT]   [' + (ei+1) + '/' + exploits.length + '] ' + e.name);
        } catch (ve) {
            console.warn('[EXPLOIT REPORT]   [' + (ei+1) + '] Mistral failed for "' + e.name + '":', ve.message);
        }
    }

    // Conclusion
    let exploitConclusionText = null;
    try {
        exploitConclusionText = await callMistral([
            { role: 'system', content: 'You are a penetration tester writing a report conclusion.' },
            { role: 'user', content: 'Write a 2-sentence conclusion for a penetration test exploit development report for ' + target + '. ' + exploits.length + ' exploits were developed. Recommend immediate remediation and retesting after fixes.' }
        ], { num_predict: 150, num_ctx: 4096, temperature: 0.3 });
        console.log('[EXPLOIT REPORT] Mistral conclusion: ' + (exploitConclusionText||'').length + ' chars');
    } catch (ce) {
        console.warn('[EXPLOIT REPORT] Mistral conclusion failed:', ce.message);
    }

    const markdown = buildExploitReportTemplate(session, exploits, execSummary, exploitConclusionText);

    const ts      = Date.now();
    const slug    = (session.target || 'manual').replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 40);
    const mdFile  = path.join(REPORTS_DIR, 'exploit_' + slug + '_' + ts + '.md');
    const pdfFile = path.join(REPORTS_DIR, 'exploit_' + slug + '_' + ts + '.pdf');

    fs.writeFileSync(mdFile, markdown, 'utf8');
    await buildPdf(session.target || 'Manual Input', new Date(session.createdAt).toLocaleDateString(), markdown, pdfFile);
    return { markdown, mdFile, pdfFile };
}

// ============================================================
// FULL REPORT (with exploit code)
// ============================================================

function buildReportMarkdown(session, overallRisk, severityCounts, toolsUsed, enrichedVulns, executiveSummary, findingDescriptions, conclusion) {
    const target = session.target;
    const date   = new Date(session.createdAt).toLocaleDateString();
    const lines  = [];

    lines.push('# ZeroTrace Penetration Testing Report');
    lines.push('');
    lines.push('| Field | Value |');
    lines.push('|-------|-------|');
    lines.push('| **Target** | ' + target + ' |');
    lines.push('| **Date** | ' + date + ' |');
    lines.push('| **Classification** | CONFIDENTIAL |');
    lines.push('| **Tool** | ZeroTrace v1.0 |');
    lines.push('| **Overall Risk** | ' + overallRisk + ' |');
    lines.push('');

    lines.push('## Executive Summary');
    lines.push('');
    lines.push(executiveSummary);
    lines.push('');

    lines.push('## Scope and Methodology');
    lines.push('');
    lines.push('The security assessment was conducted against **' + target + '** on ' + date + ' using ZeroTrace v1.0, an AI-powered penetration testing platform. The following tools were employed: ' + toolsUsed.join(', ') + '. The assessment covered network reconnaissance, vulnerability scanning, web application testing, and SQL injection detection.');
    lines.push('');

    lines.push('## Findings Summary');
    lines.push('');
    lines.push('| # | Vulnerability | Severity | CVE | Detected By |');
    lines.push('|---|--------------|----------|-----|-------------|');
    enrichedVulns.forEach(function(v, i) {
        lines.push('| ' + (i + 1) + ' | ' + v.name + ' | ' + v.severity + ' | ' + (v.cve || 'N/A') + ' | ' + (v.tool_detected_by || 'N/A') + ' |');
    });
    lines.push('');
    lines.push('**Severity Breakdown:** Critical: ' + severityCounts.Critical + ', High: ' + severityCounts.High + ', Medium: ' + severityCounts.Medium + ', Low: ' + severityCounts.Low);
    lines.push('');

    lines.push('## Detailed Findings');
    lines.push('');
    enrichedVulns.forEach(function(v, i) {
        lines.push('### ' + (i + 1) + '. ' + v.name);
        lines.push('');
        lines.push('- **Severity:** ' + v.severity);
        lines.push('- **CVE:** ' + (v.cve || 'N/A'));
        if (v.mitre_technique) lines.push('- **MITRE ATT&CK:** ' + v.mitre_technique);
        lines.push('- **Detected By:** ' + (v.tool_detected_by || 'N/A'));
        lines.push('- **Affected Component:** ' + (v.affected_component || 'N/A'));
        lines.push('');
        lines.push('**Description:**');
        lines.push((findingDescriptions && findingDescriptions[i]) || v.description || 'No description available.');
        lines.push('');
        if (v.exploitation_steps && v.exploitation_steps.length) {
            lines.push('**Exploitation Steps:**');
            v.exploitation_steps.forEach(function(step, si) {
                lines.push((si + 1) + '. ' + step.replace(/^\d+\.\s*/, ''));
            });
            lines.push('');
        }
        if (v.exploit_code) {
            lines.push('**Proof of Concept:**');
            lines.push('```python');
            lines.push(v.exploit_code.substring(0, 1000));
            lines.push('```');
            lines.push('');
        }
        lines.push('**Remediation:**');
        lines.push(v.remediation || 'Apply vendor patches and follow security best practices.');
        lines.push('');
    });

    lines.push('## Conclusion');
    lines.push('');
    if (conclusion) {
        lines.push(conclusion);
    } else {
        const critHigh = severityCounts.Critical + severityCounts.High;
        if (critHigh > 0) {
            lines.push('The assessment identified ' + enrichedVulns.length + ' vulnerabilities, including ' + critHigh + ' critical/high severity finding(s) that require immediate attention. It is strongly recommended that the identified vulnerabilities be remediated in priority order before the next assessment cycle.');
        } else {
            lines.push('The assessment identified ' + enrichedVulns.length + ' finding(s) of medium or low severity. While no critical issues were found, the identified items should be addressed to improve the overall security posture of the target application.');
        }
    }
    lines.push('');
    lines.push('---');
    lines.push('*This report was generated by ZeroTrace v1.0 — AI-Powered Penetration Testing Platform.*');
    return lines.join('\n');
}

async function buildReport(session) {
    const vulns = session.vulnerabilities || [];
    if (!vulns.length) throw new Error('No vulnerabilities to report. Analysis may have failed or target was unreachable.');

    const exploitsMap = {};
    (session.exploits || []).forEach(function(e) { exploitsMap[e.name] = e; });

    const severityOrder  = ['Critical', 'High', 'Medium', 'Low'];
    let   overallRisk    = 'Low';
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    vulns.forEach(function(v) {
        const sev = v.severity || 'Low';
        if (Object.prototype.hasOwnProperty.call(severityCounts, sev)) severityCounts[sev]++;
        if (severityOrder.indexOf(sev) < severityOrder.indexOf(overallRisk)) overallRisk = sev;
    });

    const toolsUsed = [...new Set(vulns.map(function(v) { return v.tool_detected_by; }).filter(Boolean))];
    const enrichedVulns = vulns.map(function(v) {
        const merged = Object.assign({}, v, exploitsMap[v.name] || {});
        const mitreLookup = mapMitre(merged.name);
        if (mitreLookup) merged.mitre_technique = mitreLookup.tactic + ' :: ' + mitreLookup.name + ' (' + mitreLookup.technique + ')';
        return merged;
    });

    console.log('\n════════════════════════════════════════');
    console.log('STEP 5 — REPORT GENERATION');
    console.log('[REPORT] Vulnerabilities: ' + vulns.length + '  Risk: ' + overallRisk);
    console.log('════════════════════════════════════════');

    await unloadModel(MODELS.analysis);
    await unloadModel(MODELS.exploits);

    // Search Metasploit modules
    let msfResults = [];
    try {
        msfResults = await searchMetasploitModules(vulns);
        if (msfResults.length > 0) {
            const msfByCve = {};
            msfResults.forEach(function(r) { msfByCve[r.cve] = r.modules; });
            enrichedVulns.forEach(function(v) {
                if (v.cve && msfByCve[v.cve]) v.msf_modules = msfByCve[v.cve];
            });
        }
    } catch (err) { console.warn('[REPORT] Metasploit search failed:', err.message); }

    const reportData = {
        target: session.target,
        date: new Date(session.createdAt).toLocaleDateString(),
        overallRisk, severityCounts, toolsUsed,
        findings: enrichedVulns.map(function(v) {
            return {
                name: v.name, severity: v.severity, cve: v.cve || 'N/A',
                mitre: v.mitre_technique || 'N/A', tool: v.tool_detected_by || 'N/A',
                component: v.affected_component || 'N/A', description: v.description || '',
                steps: v.exploitation_steps || [], exploit_code: (v.exploit_code || '').substring(0, 500),
                remediation: v.remediation || '', msf_modules: v.msf_modules || []
            };
        })
    };

    let markdown;
    try {
        const reportPrompt = 'Generate a complete penetration testing report in markdown format based on the following scan data. ' +
            'Follow this EXACT structure:\n\n' +
            '# ZeroTrace Penetration Testing Report\n' +
            '(metadata table with Target, Date, Classification CONFIDENTIAL, Tool ZeroTrace v1.0, Overall Risk)\n' +
            '## Executive Summary (3-4 sentences)\n' +
            '## Scope and Methodology (1 paragraph mentioning all tools used)\n' +
            '## Findings Summary (markdown table: #, Vulnerability, Severity, CVE, MITRE ATT&CK, Detected By)\n' +
            '(severity breakdown line: Critical: N, High: N, Medium: N, Low: N)\n' +
            '## Detailed Findings (for each finding: ### numbered title, bullet list with Severity/CVE/MITRE ATT&CK/Detected By/Affected Component, ' +
            'Description paragraph 2-4 sentences, Exploitation Steps numbered list, Proof of Concept in ```python code block, ' +
            'Metasploit Modules if any, Remediation paragraph)\n' +
            '## Conclusion (3-4 sentences with remediation priority)\n\n' +
            'RULES:\n' +
            '- Write professionally in third person\n' +
            '- Use proper markdown formatting with correct heading levels\n' +
            '- Include ALL findings from the data — do not skip any\n' +
            '- Descriptions should be 2-4 sentences explaining the vulnerability and its impact\n' +
            '- Code blocks must use ```python fencing and contain the exact exploit_code from the data\n' +
            '- Every word must have proper spacing between words\n' +
            '- End with: ---\\n*This report was generated by ZeroTrace v1.0 — AI-Powered Penetration Testing Platform.*\n\n' +
            'SCAN DATA:\n' + JSON.stringify(reportData, null, 2);

        console.log('[REPORT] Mistral prompt size: ' + reportPrompt.length + ' chars');
        markdown = await callMistral([
            { role: 'system', content: 'You are an expert penetration testing report writer. Generate complete, well-formatted markdown reports. Use proper spacing between all words. Every section must be present and properly formatted.' },
            { role: 'user', content: reportPrompt }
        ], { temperature: 0.3, num_ctx: 32768, num_predict: 6000 });

        if (!markdown || markdown.length < 500 || !markdown.includes('## ')) {
            throw new Error('Mistral output too short or malformed (' + (markdown || '').length + ' chars)');
        }
        console.log('[REPORT] Mistral generated full report (' + markdown.length + ' chars)');
    } catch (err) {
        console.warn('[REPORT] Mistral full report failed, using template fallback:', err.message);
        const executiveSummary = 'A penetration testing assessment was conducted against ' + session.target + '. ' +
            'The assessment identified ' + vulns.length + ' vulnerabilities with an overall risk rating of ' + overallRisk + '. ' +
            (severityCounts.Critical > 0 ? 'Critical vulnerabilities require immediate remediation.' : 'Findings warrant attention to improve security posture.') +
            ' Detailed findings and recommendations are provided below.';
        markdown = buildReportMarkdown(session, overallRisk, severityCounts, toolsUsed, enrichedVulns, executiveSummary, {}, null);
    }

    const ts      = Date.now();
    const slug    = session.target.replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 40);
    const mdFile  = path.join(REPORTS_DIR, 'zerotrace_' + slug + '_' + ts + '.md');
    const pdfFile = path.join(REPORTS_DIR, 'zerotrace_' + slug + '_' + ts + '.pdf');

    fs.writeFileSync(mdFile, markdown, 'utf8');
    console.log('[REPORT] Markdown saved: ' + mdFile);

    try {
        await buildPdf(session.target, new Date(session.createdAt).toLocaleDateString(), markdown, pdfFile);
        console.log('[REPORT] PDF saved: ' + pdfFile);
    } catch (err) {
        console.error('[REPORT] PDF generation failed:', err.message);
        throw new Error('PDF generation failed: ' + err.message);
    }

    return { markdown, mdFile, pdfFile, overallRisk };
}

// ============================================================
// PARSE VULNERABILITIES FROM USER TEXT
// ============================================================

async function parseVulnerabilitiesFromText(text) {
    try {
        const p = JSON.parse(text);
        if (p && p.vulnerabilities && Array.isArray(p.vulnerabilities)) return p.vulnerabilities;
        if (Array.isArray(p)) return p;
    } catch (_) {}

    const extracted = extractJSON(text);
    if (extracted) {
        if (extracted.vulnerabilities) return extracted.vulnerabilities;
        if (Array.isArray(extracted)) return extracted;
    }

    const prompt = 'Extract ALL security vulnerabilities from the text below and return ONLY a JSON object.\n' +
        'Format: {"vulnerabilities":[{"name":"vuln name","severity":"Critical|High|Medium|Low",' +
        '"description":"what it is","affected_component":"service:port or endpoint",' +
        '"cve":"CVE-YYYY-NNNNN or null","tool_detected_by":"tool name or manual"}]}\n\n' +
        'TEXT:\n' + text.substring(0, 10000);
    try {
        const response = await callMistral([
            { role: 'system', content: 'You are a JSON extractor. Output only valid JSON, nothing else.' },
            { role: 'user', content: prompt }
        ], { temperature: 0.05, num_ctx: 16384, num_predict: 3000 });
        const parsed = extractJSON(response);
        if (parsed && parsed.vulnerabilities) return parsed.vulnerabilities;
        if (Array.isArray(parsed)) return parsed;
    } catch (err) {
        console.error('[PARSE] Mistral extraction failed:', err.message);
    }
    return [];
}

// ============================================================
// PDF GENERATION (pdfkit)
// ============================================================

function buildPdf(target, date, markdown, outputPath) {
    return new Promise(function(resolve, reject) {
        const ML = 56.7, MR = 56.7, MT = 56.7, MB = 56.7;
        const doc = new PDFDocument({
            size: 'A4',
            margins: { top: MT, bottom: MB, left: ML, right: MR },
            bufferPages: true,
            info: {
                Title:    'ZeroTrace Penetration Testing Report',
                Author:   'ZeroTrace v1.0',
                Subject:  'Security Assessment — ' + target,
                Keywords: 'penetration testing, security, vulnerability'
            }
        });

        const stream = fs.createWriteStream(outputPath);
        doc.pipe(stream);

        const PW = doc.page.width, PH = doc.page.height, W = PW - ML - MR;

        const C = {
            black: '#0d0d0d', darkGrey: '#2c2c2c', midGrey: '#555555', lightGrey: '#aaaaaa',
            rule: '#d0d0d0', pageBg: '#ffffff', coverBg: '#0d1117', coverText: '#ffffff', coverSub: '#8b949e',
            accent: '#c0392b', accentDark: '#922b21', critical: '#c0392b', high: '#e67e22',
            medium: '#f39c12', low: '#27ae60', info: '#2980b9', codeBg: '#f6f8fa',
            codeBorder: '#d1d5db', tableHead: '#f0f2f5', tableAlt: '#fafbfc', tableRule: '#e1e4e8',
        };

        function severityColor(text) {
            const t = (text || '').toLowerCase();
            if (t.includes('critical')) return C.critical;
            if (t.includes('high'))     return C.high;
            if (t.includes('medium'))   return C.medium;
            if (t.includes('low'))      return C.low;
            return C.info;
        }

        function sectionHeading(text) {
            if (doc.y > PH - MB - 60) doc.addPage();
            doc.moveDown(0.8);
            const y = doc.y;
            doc.rect(ML, y, 3.5, 16).fill(C.accent);
            doc.rect(ML + 3.5, y, W - 3.5, 16).fill('#f6f8fa');
            doc.font('Helvetica-Bold').fontSize(11).fillColor(C.black)
               .text(text.toUpperCase(), ML + 12, y + 3, { width: W - 16, lineBreak: false });
            doc.y = y + 16 + 6;
            doc.fillColor(C.black).font('Helvetica').fontSize(9.5);
        }

        function subHeading(text) {
            if (doc.y > PH - MB - 50) doc.addPage();
            doc.moveDown(0.5);
            doc.font('Helvetica-Bold').fontSize(10.5).fillColor(C.darkGrey)
               .text(text, ML, doc.y, { width: W, align: 'left' });
            doc.rect(ML, doc.y + 2, W, 0.5).fill(C.rule);
            doc.moveDown(0.5);
            doc.font('Helvetica').fontSize(9.5).fillColor(C.black);
        }

        function minorHeading(text) {
            if (doc.y > PH - MB - 40) doc.addPage();
            doc.moveDown(0.4);
            doc.font('Helvetica-Bold').fontSize(9.5).fillColor(C.accent)
               .text(text, ML, doc.y, { width: W, align: 'left' });
            doc.moveDown(0.15);
            doc.font('Helvetica').fontSize(9.5).fillColor(C.black);
        }

        function bodyText(text) {
            if (!text || !text.trim()) { doc.moveDown(0.25); return; }
            const cleaned = text
                .replace(/\*\*(.*?)\*\*/g, '$1')
                .replace(/\*(.*?)\*/g, '$1')
                .replace(/`(.*?)`/g, '$1');
            if (doc.y > PH - MB - 20) doc.addPage();
            doc.font('Helvetica').fontSize(9.5).fillColor(C.black)
               .text(cleaned, ML, doc.y, { width: W, align: 'left', lineGap: 1.5 });
        }

        function codeBlock(codeLines) {
            if (!codeLines.length) return;
            const pad = 10, lineH = 10, maxBox = PH - MB - MT - 20;
            const linesPerPage = Math.floor((maxBox - pad * 2) / lineH);
            for (let offset = 0; offset < codeLines.length; offset += linesPerPage) {
                const chunk = codeLines.slice(offset, offset + linesPerPage);
                const boxH  = chunk.length * lineH + pad * 2;
                if (doc.y + boxH > PH - MB - 10) doc.addPage();
                const y = doc.y;
                doc.rect(ML, y, W, boxH).fill(C.codeBg);
                doc.rect(ML, y, W, boxH).stroke(C.codeBorder).lineWidth(0.5);
                doc.rect(ML, y, 3, boxH).fill(C.accent);
                doc.font('Courier').fontSize(7.8).fillColor(C.darkGrey)
                   .text(chunk.join('\n'), ML + 10, y + pad, { width: W - 20, height: boxH - pad * 2, align: 'left', lineGap: 1 });
                doc.y = y + boxH + 6;
            }
            doc.font('Helvetica').fontSize(9.5).fillColor(C.black);
        }

        function severityPill(text, x, y) {
            const color = severityColor(text);
            const label = (text || 'INFO').toUpperCase();
            const tw    = label.length * 5.2 + 10;
            doc.rect(x, y - 1, tw, 11).fill(color).opacity(0.15);
            doc.rect(x, y - 1, tw, 11).stroke(color).lineWidth(0.5).opacity(1);
            doc.font('Helvetica-Bold').fontSize(7).fillColor(color)
               .text(label, x + 5, y + 1.5, { lineBreak: false });
        }

        let tableRows = [], inTable = false;

        function flushTable() {
            if (!tableRows.length) { inTable = false; return; }
            const rows = tableRows.filter(r => !r.match(/^\|[\s-|]+\|$/));
            if (!rows.length) { tableRows = []; inTable = false; return; }
            const parsed = rows.map(r => r.replace(/^\||\|$/g, '').split('|').map(c => c.trim().replace(/\*\*(.*?)\*\*/g, '$1')));
            const cols = parsed[0].length, rowH = 18, headerH = 20, pad = 6;
            // Assign proportional column widths based on header content type
            let colW = Array(cols).fill(W / cols);
            if (cols === 6) {
                // Findings summary: #, Vulnerability, Severity, CVE, Component, Detected By
                colW = [W*0.04, W*0.28, W*0.11, W*0.15, W*0.24, W*0.18];
            } else if (cols === 5) {
                // Risk matrix or alt 5-col: #, Vuln, Sev, CVE, Detected By
                colW = [W*0.05, W*0.32, W*0.12, W*0.18, W*0.33];
            } else if (cols === 4) {
                colW = [W*0.05, W*0.45, W*0.28, W*0.22];
            } else if (cols >= 7) {
                colW[0] = W * 0.04; const rest = (W - colW[0]) / (cols - 1); for (let i = 1; i < cols; i++) colW[i] = rest;
            }
            if (doc.y + headerH > PH - MB - 10) doc.addPage();
            const hY = doc.y;
            doc.rect(ML, hY, W, headerH).fill(C.tableHead);
            doc.rect(ML, hY, W, headerH).stroke(C.tableRule).lineWidth(0.3);
            let xCur = ML;
            parsed[0].forEach(function(cell, ci) {
                doc.font('Helvetica-Bold').fontSize(8).fillColor(C.darkGrey)
                   .text(cell, xCur + pad, hY + 6, { width: colW[ci] - pad * 2, lineBreak: false, align: 'left' });
                xCur += colW[ci];
            });
            doc.y = hY + headerH;
            parsed.slice(1).forEach(function(row, ri) {
                if (doc.y + rowH > PH - MB - 10) doc.addPage();
                const rY = doc.y;
                if (ri % 2 === 1) doc.rect(ML, rY, W, rowH).fill(C.tableAlt);
                doc.rect(ML, rY, W, rowH).stroke(C.tableRule).lineWidth(0.3);
                let xr = ML;
                row.forEach(function(cell, ci) {
                    const hdr = (parsed[0][ci] || '').toLowerCase();
                    const isSev = hdr.includes('sever') || hdr.includes('risk');
                    if (isSev && cell) {
                        severityPill(cell, xr + pad, rY + 4);
                    } else {
                        doc.font('Helvetica').fontSize(8).fillColor(C.black)
                           .text(cell, xr + pad, rY + 5, { width: colW[ci] - pad * 2, lineBreak: false, align: 'left' });
                    }
                    xr += colW[ci];
                });
                doc.y = rY + rowH;
            });
            doc.moveDown(0.5);
            tableRows = []; inTable = false;
        }

        // Cover page
        doc.rect(0, 0, PW, PH).fill('#ffffff');
        doc.rect(0, 0, 6, PH).fill(C.accent);
        doc.rect(PW - 90, 0, 90, 90).fill('#f6f8fa');
        doc.rect(PW - 90, 0, 2, 90).fill(C.accent);

        const logoPath = path.join(__dirname, '../../frontend/black-logo.png');
        const wLogo    = path.join(__dirname, '../../frontend/logo.png');
        const useLogo  = fs.existsSync(logoPath) ? logoPath : (fs.existsSync(wLogo) ? wLogo : null);
        if (useLogo) {
            doc.image(useLogo, ML + 6, 60, { width: 220 });
        } else {
            doc.font('Helvetica-Bold').fontSize(32).fillColor(C.accent).text('ZeroTrace', ML + 6, 60, { lineBreak: false });
        }

        doc.rect(ML + 6, 130, W - 6, 1).fill(C.rule);
        doc.font('Helvetica-Bold').fontSize(8).fillColor(C.accent)
           .text('SECURITY ASSESSMENT REPORT', ML + 6, 148, { lineBreak: false, characterSpacing: 1.5 });
        doc.rect(ML + 6, 166, 4, 64).fill(C.accent);
        doc.font('Helvetica-Bold').fontSize(26).fillColor(C.black).text('Penetration', ML + 18, 166, { lineBreak: false });
        doc.font('Helvetica-Bold').fontSize(26).fillColor(C.black).text('Testing Report', ML + 18, 198, { lineBreak: false });
        doc.rect(ML + 6, 248, W - 6, 0.75).fill(C.accent);

        const metaItems = [
            ['Target',           target],
            ['Assessment Date',  date],
            ['Classification',   'CONFIDENTIAL'],
            ['Prepared By',      'ZeroTrace v1.0 — AI Penetration Testing Platform'],
        ];
        const metaY = 268;
        const labelW = 110;
        metaItems.forEach(function(item, i) {
            const my = metaY + i * 26;
            if (i > 0) doc.rect(ML + 6, my - 5, W - 6, 0.3).fill(C.rule);
            doc.font('Helvetica-Bold').fontSize(8).fillColor(C.midGrey)
               .text(item[0].toUpperCase(), ML + 6, my, { width: labelW, lineBreak: false, characterSpacing: 0.5 });
            doc.font('Helvetica').fontSize(9).fillColor(C.black)
               .text(item[1], ML + 6 + labelW, my, { width: W - labelW - 6, lineBreak: false });
        });

        const badgeY = metaY + metaItems.length * 26 + 20;
        const badgeW = 160;
        doc.rect(ML + 6, badgeY, badgeW, 22).fill(C.accent);
        doc.font('Helvetica-Bold').fontSize(8).fillColor('#ffffff')
           .text('CONFIDENTIAL — NOT FOR DISTRIBUTION', ML + 14, badgeY + 7, { width: badgeW - 16, lineBreak: false });

        doc.rect(0, PH - 40, PW, 40).fill('#f6f8fa');
        doc.rect(0, PH - 40, PW, 1).fill(C.rule);
        doc.rect(0, PH - 40, 6, 40).fill(C.accent);
        doc.font('Helvetica').fontSize(7.5).fillColor(C.lightGrey)
           .text('Generated by ZeroTrace v1.0  |  AI-Powered Penetration Testing Platform', ML + 14, PH - 26, { lineBreak: false });

        // Content pages
        doc.addPage();
        doc.fillColor(C.black).font('Helvetica').fontSize(9.5);
        let inCode = false;
        const codeBuf = [];
        const lines = markdown.split('\n');

        lines.forEach(function(line) {
            if (line.startsWith('```')) {
                if (inCode) { codeBlock(codeBuf.slice()); codeBuf.length = 0; inCode = false; }
                else        { if (inTable) flushTable(); inCode = true; }
                return;
            }
            if (inCode) { codeBuf.push(line); return; }
            if (line.startsWith('|')) {
                inTable = true; tableRows.push(line); return;
            } else if (inTable) { flushTable(); }

            if (line.startsWith('# ')) {
                sectionHeading(line.slice(2));
            } else if (line.startsWith('## ')) {
                subHeading(line.slice(3));
            } else if (line.startsWith('### ')) {
                minorHeading(line.slice(4));
            } else if (line.startsWith('- ') || line.startsWith('* ')) {
                const txt = line.slice(2).replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1');
                if (doc.y > PH - MB - 20) doc.addPage();
                doc.font('Helvetica').fontSize(9.5).fillColor(C.black)
                   .text('\u2022', ML + 6, doc.y, { width: 10, lineBreak: false });
                doc.text(txt, ML + 18, doc.y - doc.currentLineHeight(), { width: W - 18, align: 'left', lineGap: 1.5 });
            } else if (/^\d+\.\s/.test(line)) {
                const num = line.match(/^\d+/)[0];
                const txt = line.replace(/^\d+\.\s+/, '').replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1');
                if (doc.y > PH - MB - 20) doc.addPage();
                doc.font('Helvetica').fontSize(9.5).fillColor(C.black)
                   .text(num + '.', ML + 6, doc.y, { width: 14, lineBreak: false });
                doc.text(txt, ML + 22, doc.y - doc.currentLineHeight(), { width: W - 22, align: 'left', lineGap: 1.5 });
            } else {
                bodyText(line);
            }
        });

        if (inCode && codeBuf.length)  codeBlock(codeBuf);
        if (inTable && tableRows.length) flushTable();

        // Header + footer on every content page
        const range = doc.bufferedPageRange();
        for (let i = 0; i < range.count; i++) {
            doc.switchToPage(range.start + i);
            if (i === 0) continue;
            doc.rect(ML, 20, W, 0.5).fill(C.rule);
            doc.font('Helvetica-Bold').fontSize(7).fillColor(C.lightGrey).text('ZEROTRACE', ML, 10, { lineBreak: false });
            doc.font('Helvetica').fontSize(7).fillColor(C.lightGrey)
               .text('Penetration Testing Report — CONFIDENTIAL', ML, 10, { align: 'right', width: W });
            const fy = PH - MB + 14;
            doc.rect(ML, fy - 6, W, 0.5).fill(C.rule);
            doc.font('Helvetica').fontSize(7).fillColor(C.lightGrey).text(target + '  |  ' + date, ML, fy, { lineBreak: false });
            doc.font('Helvetica').fontSize(7).fillColor(C.lightGrey)
               .text('Page ' + i + ' of ' + (range.count - 1), ML, fy, { align: 'right', width: W });
        }

        doc.end();
        stream.on('finish', resolve);
        stream.on('error',  reject);
    });
}

module.exports = {
    buildVulnReport, buildReport, buildExploitReport,
    buildVulnReportTemplate, buildExploitReportTemplate, buildReportMarkdown,
    buildPdf, parseVulnerabilitiesFromText,
    severityToImpact, severityToLikelihood, truncateComponent, cleanDescription
};
