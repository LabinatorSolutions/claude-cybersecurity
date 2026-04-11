<p align="center">
  <img src="assets/banner.webp" alt="claude-cybersecurity: AI-Powered Code Security Audit" width="100%">
</p>

<p align="center">
  <a href="https://github.com/AgriciDaniel/claude-cybersecurity/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/claude--code-skill-blueviolet" alt="Claude Code Skill">
  <img src="https://img.shields.io/badge/agents-8-00ff88" alt="8 Specialist Agents">
  <img src="https://img.shields.io/badge/CWE%20Top%2025-100%25-red" alt="CWE Top 25 Coverage">
  <img src="https://img.shields.io/badge/OWASP-2025-orange" alt="OWASP 2025">
  <img src="https://img.shields.io/badge/languages-11-blue" alt="11 Languages">
</p>

---

**The most comprehensive AI-powered cybersecurity code review skill for Claude Code.** Spawns 8 parallel specialist agents to audit your codebase across vulnerability detection, authorization verification, secret scanning, supply chain analysis, IaC security, threat intelligence (malware/C2/backdoor detection), AI-generated code patterns, and business logic flaws.

**Surpasses GitHub Advanced Security** by detecting what static tools architecturally cannot: missing security controls, business logic flaws, attack-path chaining, and obfuscated secrets — with zero configuration.

---

## Installation

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/AgriciDaniel/claude-cybersecurity/main/install.sh | bash
```

### Manual

```bash
git clone https://github.com/AgriciDaniel/claude-cybersecurity.git
cd claude-cybersecurity
bash install.sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/AgriciDaniel/claude-cybersecurity/main/install.ps1 | iex
```

## Quick Start

```bash
# Full security audit of current project
/cybersecurity

# Quick scan (entry points + auth + secrets + deps only)
/cybersecurity --scope quick

# Review only changed files (PR review mode)
/cybersecurity --scope diff

# Deep dive into one dimension
/cybersecurity --focus threat

# With compliance mapping
/cybersecurity --compliance pci
```

## What It Does

| Agent | Weight | Focus |
|-------|--------|-------|
| Vulnerability Scanner | 20% | OWASP Top 10:2025 + CWE Top 25:2024, taint analysis, injection patterns |
| Authorization Reviewer | 15% | Auth bypass, IDOR, privilege escalation, session management |
| Threat Intelligence | 15% | Malware indicators, backdoors, C2 communication, MITRE ATT&CK mapping |
| Secret Scanner | 10% | Semantic detection, split/obfuscated credentials, .env exposure |
| Dependency Auditor | 10% | Supply chain, slopsquatting, typosquatting, behavioral analysis |
| IaC Scanner | 10% | Terraform, Docker, Kubernetes, GitHub Actions misconfigurations |
| AI Code Auditor | 10% | AI-generated code patterns (missing validation, hallucinated deps) |
| Logic Reviewer | 10% | Business logic flaws, race conditions, TOCTOU, attack-path chaining |

## Key Differentiators vs GitHub Advanced Security

| Capability | GHAS | This Skill |
|------------|------|-----------|
| Business logic flaw detection | No | Yes |
| Authorization enforcement verification | Basic | Context-aware |
| Race condition detection | Very limited | Concurrency pattern analysis |
| Languages supported | 12 | 16+ (any language) |
| IaC/Container/CI-CD scanning | No | Terraform, Docker, K8s, Actions |
| AI-generated code security | No | Specialized detection |
| Obfuscated secret detection (84.4% recall) | Regex only | Semantic understanding |
| Threat intelligence (malware/C2) | No | MITRE ATT&CK mapped |
| Framework-aware false-positive suppression | No | 10 frameworks |
| Cost | $49/committer/month | Free (with Claude Code) |

## Coverage

### Standards
- OWASP Top 10:2025 (all 10 categories including new A03 Supply Chain + A10 Exceptional Conditions)
- CWE Top 25:2024 (25 dedicated detection sections)
- OWASP API Security Top 10:2023
- MITRE ATT&CK v15 (7 techniques: T1059, T1027, T1071, T1195, T1005, T1041, T1496)

### Languages (11 pattern files)
Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, Ruby, PHP, C#/.NET, Swift/Kotlin, Shell/Bash

### IaC Platforms
Terraform (AWS/GCP/Azure), Dockerfile, Kubernetes YAML, GitHub Actions workflows

### Compliance Frameworks
PCI DSS 4.0, HIPAA, SOC 2, GDPR, NIST SP 800-53

## Scoring System

```
Finding Score = Base Severity (CVSS-aligned, 0-100)
              x Confidence Multiplier (0.3-1.0)
              x Exploitability Factor (0.5-1.0)
              +/- Context Adjustment (-20 to +20)
```

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent security posture |
| B | 75-89 | Good with minor issues |
| C | 50-74 | Needs significant improvement |
| D | 25-49 | Serious security concerns |
| F | 0-24 | Critical — immediate action required |

## Architecture

```
/cybersecurity [path] [--scope full|quick|diff] [--compliance pci|hipaa|soc2|gdpr]
    |
    v
 GATHER: Detect stack, enumerate entry points, map trust boundaries
    |
    v
 ANALYZE: 8 parallel specialist agents (single dispatch)
    |
    v
 RECOMMEND: Weighted aggregation, attack-path chaining, compliance mapping
    |
    v
 EXECUTE: Structured report with prioritized remediation
```

## File Structure

```
skills/cybersecurity/
├── SKILL.md                              (900 lines — orchestrator)
├── references/
│   ├── vulnerability-taxonomy.md         (25 CWE categories)
│   ├── scoring-rubric.md                 (formula + confidence system)
│   ├── threat-intelligence.md            (MITRE ATT&CK patterns)
│   ├── compliance-matrix.md              (5 frameworks)
│   ├── false-positive-suppression.md     (10 frameworks)
│   ├── semgrep-patterns.md              (8 detection patterns)
│   ├── report-template.md               (output format + worked example)
│   ├── language-patterns/               (11 files)
│   └── iac-patterns/                    (4 files)
```

**Total: 23 files, 5,350 lines of security knowledge.**

## Requirements

- [Claude Code](https://claude.ai/code) (CLI, Desktop, or IDE extension)
- No other dependencies — zero configuration, works immediately

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/AgriciDaniel/claude-cybersecurity/main/uninstall.sh | bash
```

Or manually:
```bash
rm -rf ~/.claude/skills/cybersecurity
```

## Related Projects

- [claude-seo](https://github.com/AgriciDaniel/claude-seo) — Comprehensive SEO analysis
- [claude-blog](https://github.com/AgriciDaniel/claude-blog) — Full-lifecycle blog engine
- [claude-ads](https://github.com/AgriciDaniel/claude-ads) — Paid advertising audit

## License

[MIT](LICENSE) - AgriciDaniel 2026
