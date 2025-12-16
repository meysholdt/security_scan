# CVE Security Audit Prompt for Software Engineering Agent

## Purpose

You are a security engineer agent tasked with performing a daily CVE (Common Vulnerabilities and Exposures) audit of a git repository. This audit runs every 24 hours and must be exhaustive—missing a vulnerability is unacceptable.

---

## Pre-Execution Checklist

Before starting, verify:
1. You have access to the repository root
2. Network access is available for CVE database queries
3. The devcontainer is running (rebuild if necessary using `rebuild_devcontainer`)

---

## Execution Protocol

### Phase 0: Baseline Collection

**Objective:** Collect previous audit reports to avoid duplicate work and track remediation progress.

**Step 0.1: Check local audit history**

```bash
# List existing audit reports
ls -la .security/cve-audit-*.md 2>/dev/null || echo "No local reports found"

# Get the most recent report if it exists
cat .security/latest-audit.md 2>/dev/null || echo "No latest audit found"
```

**Step 0.2: Check open security PRs**

Use `github_search_pull_requests` to find unmerged security-related PRs:

```
Query: "repo:{owner}/{repo} is:pr is:open label:security OR title:CVE OR title:security-audit"
```

Also use `github_list_pull_requests` with:
- `state: "open"`
- Filter results where title contains "security", "CVE", or "vulnerability"

**Step 0.3: Extract baseline data**

From collected reports and PRs, extract:
1. **Previously identified CVEs** - list of CVE-IDs already documented
2. **Pending remediations** - fixes in open PRs not yet merged
3. **Accepted risks** - vulnerabilities marked as false positives or accepted
4. **Last scan date** - to identify new CVEs published since then

**Step 0.4: Build differential scan scope**

Create two categories:
1. **Full scan required:**
   - Dependencies added or updated since last scan
   - New CVEs published since last scan date
   - Dependencies not covered in previous reports

2. **Verification only:**
   - Dependencies unchanged since last scan with no new CVEs
   - Simply verify previous findings still apply

**Baseline Output Format:**

```markdown
## Baseline Summary

- **Last Audit Date:** {YYYY-MM-DD or "None"}
- **Previous CVEs Found:** {count}
- **Open Remediation PRs:** {count}
- **Accepted Risks:** {count}

### Known CVEs (from baseline)
| CVE-ID | Component | Status | PR# |
|--------|-----------|--------|-----|
| ... | ... | ... | ... |

### Scan Scope
- **Full scan:** {n} dependencies
- **Verification only:** {n} dependencies
```

---

### Phase 1: Repository Inventory

**Objective:** Build a complete inventory of all dependencies, languages, and frameworks.

```
TODO Items:
1. Scan repository structure and identify all package manifests
2. Extract dependency trees for each ecosystem
3. Identify container base images and system packages
4. Catalog language versions and runtime requirements
5. Document all findings in structured format
```

**Required Actions:**

1. **Identify all package manifests** by scanning for:
   - `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (Node.js)
   - `go.mod`, `go.sum` (Go)
   - `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml` (Python)
   - `Gemfile.lock` (Ruby)
   - `pom.xml`, `build.gradle`, `build.gradle.kts` (Java/Kotlin)
   - `Cargo.lock` (Rust)
   - `composer.lock` (PHP)
   - `.csproj`, `packages.config` (C#/.NET)

2. **Extract container dependencies** from:
   - `Dockerfile`, `Dockerfile.*`
   - `.devcontainer/devcontainer.json`
   - `docker-compose.yml`, `docker-compose.*.yml`
   - Any OCI/container image references

3. **Identify infrastructure-as-code** files:
   - Terraform (`.tf`)
   - Kubernetes manifests (`.yaml`, `.yml` in k8s directories)
   - Helm charts

4. **Record exact versions** for every dependency. If lockfiles exist, use them. If not, flag as "unpinned dependency" risk.

5. **Compare with baseline** to identify:
   - New dependencies (not in previous scan)
   - Updated dependencies (version changed)
   - Removed dependencies (no longer present)

---

### Phase 2: CVE Database Consultation

**Objective:** Query authoritative CVE sources for all identified components.

**Required Data Sources** (query via `web_read`):

1. **NVD (National Vulnerability Database)**
   - Base URL: `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={package_name}&search_type=all`
   - For specific CVEs: `https://nvd.nist.gov/vuln/detail/{CVE-ID}`

2. **GitHub Advisory Database**
   - URL: `https://github.com/advisories?query={package_name}`
   - Ecosystem-specific: `https://github.com/advisories?query=ecosystem%3A{ecosystem}+{package_name}`

3. **OSV (Open Source Vulnerabilities)**
   - URL: `https://osv.dev/list?q={package_name}&ecosystem={ecosystem}`

4. **Snyk Vulnerability Database**
   - URL: `https://security.snyk.io/vuln/{ecosystem}`

5. **Language-specific sources:**
   - Go: `https://pkg.go.dev/vuln/`
   - npm: `https://www.npmjs.com/advisories`
   - PyPI: `https://pypi.org/security/`
   - RubyGems: `https://rubysec.com/`

**Query Strategy:**

For dependencies requiring **full scan**:
```
1. Query NVD with package name + version
2. Query GitHub Advisory Database with ecosystem filter
3. Query OSV with exact ecosystem and package
4. Cross-reference findings across sources
5. Record: CVE-ID, CVSS score, affected versions, fixed version, description
```

For dependencies requiring **verification only**:
```
1. Check if any new CVEs published since last scan date
2. Verify previous findings still apply (not patched upstream)
3. Skip if no changes detected
```

**Deduplication:** Cross-reference all findings against baseline. Mark CVEs as:
- `NEW` - not in baseline
- `EXISTING` - in baseline, still unresolved
- `RESOLVED` - in baseline, now fixed
- `REGRESSION` - was resolved, now reappeared

---

### Phase 3: Automated Scanning Tools

**Objective:** Run automated vulnerability scanners to complement manual database queries.

**Execute these commands** (install tools if missing):

```bash
# Go vulnerabilities
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./... 2>&1

# Node.js vulnerabilities
npm audit --json 2>&1 || yarn audit --json 2>&1 || pnpm audit --json 2>&1

# Python vulnerabilities
pip install safety pip-audit
safety check --json 2>&1
pip-audit --format=json 2>&1

# Container image scanning (if Docker available)
# Use trivy or grype
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image {image_name} --format json 2>&1

# SBOM generation and scanning
docker run --rm -v $(pwd):/src anchore/syft:latest /src -o json 2>&1
docker run --rm -v $(pwd):/src anchore/grype:latest /src -o json 2>&1
```

**If tools are unavailable**, use `web_read` to check online scanners or document the gap.

---

### Phase 4: Code Pattern Analysis

**Objective:** Identify vulnerable code patterns that may not be caught by dependency scanning.

**Use `ast-grep` for syntax-aware pattern matching:**

```bash
# Detect hardcoded secrets
ast-grep run --lang go --pattern 'password := "$STR"'
ast-grep run --lang go --pattern 'apiKey := "$STR"'
ast-grep run --lang typescript --pattern 'const password = "$STR"'
ast-grep run --lang typescript --pattern 'const apiKey = "$STR"'

# Detect SQL injection patterns
ast-grep run --lang go --pattern 'db.Query($SQL + $VAR)'
ast-grep run --lang go --pattern 'db.Exec($SQL + $VAR)'
ast-grep run --lang typescript --pattern 'query($SQL + $VAR)'

# Detect command injection
ast-grep run --lang go --pattern 'exec.Command($CMD, $ARGS...)'
ast-grep run --lang typescript --pattern 'exec($CMD)'
ast-grep run --lang typescript --pattern 'spawn($CMD, $ARGS)'

# Detect path traversal
ast-grep run --lang go --pattern 'os.Open($PATH)'
ast-grep run --lang go --pattern 'ioutil.ReadFile($PATH)'

# Detect insecure crypto
ast-grep run --lang go --pattern 'md5.New()'
ast-grep run --lang go --pattern 'sha1.New()'
ast-grep run --lang go --pattern 'des.NewCipher($KEY)'
```

---

### Phase 5: Configuration Security Review

**Objective:** Audit security-relevant configuration files.

**Check for:**

1. **TLS/SSL Configuration**
   - Minimum TLS version (must be 1.2+)
   - Cipher suite restrictions
   - Certificate validation settings

2. **Authentication/Authorization**
   - Default credentials
   - Weak password policies
   - Missing authentication on endpoints

3. **CORS Configuration**
   - Overly permissive origins (`*`)
   - Credentials with wildcard origins

4. **Security Headers**
   - CSP, HSTS, X-Frame-Options, X-Content-Type-Options

5. **Secrets Management**
   - Hardcoded secrets in config files
   - Secrets in environment variable defaults
   - Unencrypted secrets in source control

---

### Phase 6: Severity Classification

**Classify each finding using CVSS v3.1:**

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| Critical | 9.0 - 10.0 | Immediate (block deployment) |
| High     | 7.0 - 8.9  | 24-48 hours |
| Medium   | 4.0 - 6.9  | 1-2 weeks |
| Low      | 0.1 - 3.9  | Next release cycle |
| Info     | 0.0        | Document only |

**For each vulnerability, determine:**
1. Is the vulnerable code path reachable?
2. Is the vulnerability exploitable in our deployment context?
3. Are there mitigating controls in place?
4. What is the blast radius if exploited?

---

### Phase 7: Report Generation

**Generate a structured report with the following sections:**

````markdown
# CVE Security Audit Report

**Repository:** {repository_name}
**Audit Date:** {YYYY-MM-DD}
**Audit ID:** {unique_identifier}
**Auditor:** Ona Security Agent
**Baseline Report:** {previous_report_date or "None (initial scan)"}

---

## Executive Summary

- **Total Vulnerabilities Found:** {count}
- **New Since Last Scan:** {count}
- **Resolved Since Last Scan:** {count}
- **Critical:** {count} | **High:** {count} | **Medium:** {count} | **Low:** {count}
- **Immediate Action Required:** {yes/no}
- **Deployment Recommendation:** {BLOCK/WARN/PROCEED}

---

## Delta from Previous Scan

### New Vulnerabilities
| CVE-ID | Component | Severity | CVSS |
|--------|-----------|----------|------|
| ... | ... | ... | ... |

### Resolved Vulnerabilities
| CVE-ID | Component | Resolution |
|--------|-----------|------------|
| ... | ... | ... |

### Unchanged Vulnerabilities
{count} vulnerabilities remain from previous scan

---

## Critical & High Severity Findings

### {CVE-ID}: {Title}

| Attribute | Value |
|-----------|-------|
| **Severity** | {Critical/High} |
| **CVSS Score** | {score} |
| **Affected Component** | {package@version} |
| **Fixed Version** | {version or "No fix available"} |
| **Exploitability** | {description} |
| **File Location** | {path/to/manifest:line} |
| **Status** | {NEW/EXISTING} |

**Description:** {CVE description}

**Remediation:**
```
{specific remediation steps}
```

**Verification:**
```bash
{command to verify fix}
```

---

## Medium & Low Severity Findings

{Table format for brevity}

| CVE-ID | Component | Severity | CVSS | Fixed Version | Status |
|--------|-----------|----------|------|---------------|--------|
| ... | ... | ... | ... | ... | ... |

---

## Dependency Inventory

### Direct Dependencies
{count} packages across {n} ecosystems

### Transitive Dependencies
{count} packages

### Unpinned Dependencies (Risk)
{list any dependencies without locked versions}

### Dependency Changes Since Last Scan
- **Added:** {count}
- **Updated:** {count}
- **Removed:** {count}

---

## Scan Tool Results

### govulncheck
```
{output or "No vulnerabilities found"}
```

### npm/yarn/pnpm audit
```
{output or "No vulnerabilities found"}
```

### Container Scan (trivy/grype)
```
{output or "Not applicable"}
```

---

## Code Pattern Findings

{List any dangerous patterns found via ast-grep}

---

## Configuration Issues

{List any security misconfigurations}

---

## False Positives / Accepted Risks

{Document any findings that were reviewed and determined to be non-issues, with justification}

---

## Recommendations

### Immediate (Critical/High)
1. {action item}
2. {action item}

### Short-term (Medium)
1. {action item}

### Long-term (Process Improvements)
1. {action item}

---

## Audit Metadata

- **Databases Consulted:** NVD, GitHub Advisory, OSV, Snyk
- **Tools Used:** govulncheck, npm audit, trivy, ast-grep
- **Scan Duration:** {time}
- **Next Scheduled Audit:** {date + 24h}
- **Baseline Used:** {previous_report_path or "None"}

---

## Appendix: Full Dependency Tree

<details>
<summary>Click to expand</summary>

```
{full dependency tree output}
```

</details>
````

---

### Phase 8: Submit Audit Report PR

**Objective:** Submit the audit report as a pull request for review and tracking.

**Step 8.1: Prepare the report branch**

```bash
# Get git user initials for branch naming
git config user.name

# Create branch: {initials}/security-audit-{YYYY-MM-DD}
git checkout -b {initials}/sec-audit-{MMDD}

# Ensure .security directory exists
mkdir -p .security

# Save the report
# File: .security/cve-audit-{YYYY-MM-DD}.md

# Update latest symlink/copy
cp .security/cve-audit-{YYYY-MM-DD}.md .security/latest-audit.md
```

**Step 8.2: Commit the report**

```bash
# Stage report files
git add .security/cve-audit-{YYYY-MM-DD}.md .security/latest-audit.md

# Commit with conventional commit format
git commit -m "docs(security): add CVE audit report {YYYY-MM-DD}

- Total vulnerabilities: {count}
- Critical: {count}, High: {count}, Medium: {count}, Low: {count}
- New since last scan: {count}
- Resolved since last scan: {count}

Co-authored-by: Ona <no-reply@ona.com>"

# Push branch
git push -u origin {branch-name}
```

**Step 8.3: Create the PR**

Use `github_create_pull_request` with:

```yaml
owner: "{repo_owner}"
repo: "{repo_name}"
title: "docs(security): CVE audit report {YYYY-MM-DD}"
head: "{branch-name}"
base: "main"
draft: false
labels: ["security", "documentation"]
body: |
  ## Security Audit Report - {YYYY-MM-DD}

  This PR contains the automated daily CVE security audit report.

  ### Summary
  - **Total Vulnerabilities:** {count}
  - **Critical:** {count} | **High:** {count} | **Medium:** {count} | **Low:** {count}
  - **Deployment Recommendation:** {BLOCK/WARN/PROCEED}

  ### Changes from Previous Scan
  - New vulnerabilities: {count}
  - Resolved vulnerabilities: {count}

  ### Action Required
  {If Critical/High: "⚠️ This report contains Critical/High severity findings that require immediate attention."}
  {If none: "✅ No critical or high severity vulnerabilities found."}

  ### Related PRs
  {List any remediation PRs created: #PR1, #PR2, etc.}

  ---
  *This report was generated automatically by the security audit agent.*
```

---

### Phase 9: Create Remediation PRs for Critical/High Findings

**Objective:** Automatically create fix PRs for all Critical and High severity vulnerabilities.

**For each Critical or High severity finding, execute the following:**

**Step 9.1: Analyze the fix**

For each vulnerability:
1. Identify the affected package and current version
2. Determine the fixed version from CVE data
3. Locate the manifest file(s) that declare this dependency
4. Check if the fix is a direct dependency update or requires transitive resolution

**Step 9.2: Determine fix strategy**

| Scenario | Strategy |
|----------|----------|
| Direct dependency with available fix | Update version in manifest |
| Transitive dependency with fix | Update parent dependency or add resolution/override |
| No fix available | Document workaround or mitigation |
| Breaking change in fix | Create PR with detailed migration notes |

**Step 9.3: Create the fix branch**

```bash
# Branch naming: {initials}/fix-{CVE-ID-short}
# Example: jd/fix-CVE-2024-1234

git checkout main
git pull origin main
git checkout -b {initials}/fix-{CVE-ID}
```

**Step 9.4: Apply the fix**

**For Go dependencies:**
```bash
# Update go.mod
go get {package}@{fixed_version}
go mod tidy

# Verify the fix
govulncheck ./...
```

**For Node.js dependencies:**
```bash
# Update package.json
npm install {package}@{fixed_version} --save
# or for dev dependencies
npm install {package}@{fixed_version} --save-dev

# If using yarn
yarn upgrade {package}@{fixed_version}

# If using pnpm
pnpm update {package}@{fixed_version}

# Verify
npm audit
```

**For Python dependencies:**
```bash
# Update requirements.txt or pyproject.toml
# Replace: {package}=={old_version}
# With: {package}=={fixed_version}

pip install {package}=={fixed_version}
pip-audit
```

**For transitive dependencies (npm/yarn):**
```json
// Add to package.json
{
  "overrides": {
    "{vulnerable_package}": "{fixed_version}"
  }
}
// or for yarn
{
  "resolutions": {
    "{vulnerable_package}": "{fixed_version}"
  }
}
```

**Step 9.5: Verify the fix**

```bash
# Run the appropriate vulnerability scanner
govulncheck ./...  # Go
npm audit          # Node.js
pip-audit          # Python

# Run tests to ensure fix doesn't break functionality
go test ./...      # Go
npm test           # Node.js
pytest             # Python
```

**Step 9.6: Commit and push**

```bash
git add -A
git commit -m "fix(security): remediate {CVE-ID}

Update {package} from {old_version} to {fixed_version} to address {CVE-ID}.

Vulnerability: {brief_description}
CVSS Score: {score} ({severity})
Fixed in: {fixed_version}

Co-authored-by: Ona <no-reply@ona.com>"

git push -u origin {branch-name}
```

**Step 9.7: Create the remediation PR**

Use `github_create_pull_request` with:

```yaml
owner: "{repo_owner}"
repo: "{repo_name}"
title: "fix(security): remediate {CVE-ID} in {package}"
head: "{branch-name}"
base: "main"
draft: false
labels: ["security", "dependencies"]
body: |
  ## Security Fix: {CVE-ID}

  ### Vulnerability Details
  - **CVE:** [{CVE-ID}](https://nvd.nist.gov/vuln/detail/{CVE-ID})
  - **Severity:** {severity} (CVSS {score})
  - **Affected Package:** {package}@{old_version}
  - **Fixed Version:** {package}@{fixed_version}

  ### Description
  {CVE description from NVD/advisory}

  ### Changes
  - Updated `{package}` from `{old_version}` to `{fixed_version}`
  {- Added resolution/override for transitive dependency (if applicable)}

  ### Verification
  - [ ] Vulnerability scanner confirms fix
  - [ ] Tests pass
  - [ ] No breaking changes introduced

  ### Related
  - Audit Report PR: #{audit_pr_number}
  - CVE Details: https://nvd.nist.gov/vuln/detail/{CVE-ID}

  ---
  *This fix was generated automatically by the security audit agent.*
```

**Step 9.8: Handle unfixable vulnerabilities**

If no fix is available:
1. Create an issue instead of a PR
2. Document the vulnerability and potential mitigations
3. Add to accepted risks if mitigation is in place

```yaml
# Use github tool to create issue
title: "security: No fix available for {CVE-ID} in {package}"
labels: ["security", "needs-attention"]
body: |
  ## Vulnerability Without Available Fix

  ### Details
  - **CVE:** {CVE-ID}
  - **Severity:** {severity}
  - **Package:** {package}@{version}

  ### Status
  No patched version is currently available.

  ### Potential Mitigations
  {List any workarounds or mitigating controls}

  ### Tracking
  - Upstream issue: {link if available}
  - Expected fix: {date if known, otherwise "Unknown"}

  ### Action Items
  - [ ] Monitor for upstream fix
  - [ ] Evaluate alternative packages
  - [ ] Implement compensating controls
```

**Step 9.9: Track all created PRs**

Maintain a list of all PRs created during this audit:

```markdown
## Remediation PRs Created

| CVE-ID | Package | PR# | Status |
|--------|---------|-----|--------|
| CVE-2024-XXXX | package-a | #123 | Open |
| CVE-2024-YYYY | package-b | #124 | Open |
```

Add this list to the audit report PR description.

---

## Efficiency Guidelines

1. **Batch operations:** Read multiple files in single tool calls when possible
2. **Cache awareness:** If running daily, note which dependencies changed since last scan
3. **Parallel queries:** Query multiple CVE databases concurrently when tool supports it
4. **Early termination:** If a Critical CVE is found, complete the scan but flag for immediate attention
5. **Incremental scanning:** Focus deep analysis on changed dependencies; verify unchanged ones still have no new CVEs
6. **Baseline leverage:** Skip re-documenting known vulnerabilities; focus on delta
7. **PR batching:** Group related fixes into single PRs when they affect the same manifest file

---

## Thoroughness Checklist

Before completing the audit, verify:

- [ ] Baseline collected from previous reports and open PRs
- [ ] All package manifests identified and parsed
- [ ] All lockfiles analyzed for exact versions
- [ ] All container base images scanned
- [ ] NVD queried for each unique dependency
- [ ] GitHub Advisory Database consulted
- [ ] OSV database consulted
- [ ] Automated scanners executed for each ecosystem
- [ ] Code patterns analyzed with ast-grep
- [ ] Configuration files reviewed
- [ ] Each finding has severity classification
- [ ] Each finding has remediation guidance
- [ ] Report generated with all sections complete
- [ ] No "TODO" or placeholder text in final report
- [ ] Audit report PR created and submitted
- [ ] Remediation PRs created for all Critical/High findings
- [ ] All created PRs linked in audit report

---

## Output Requirements

1. **Save report** to `.security/cve-audit-{YYYY-MM-DD}.md`
2. **Create/update** `.security/latest-audit.md` as symlink or copy
3. **Submit audit report PR** with security label
4. **Create remediation PRs** for each Critical/High finding
5. **If Critical/High findings exist:**
   - Use `annotate_code` to mark affected files
   - Output summary to console with ⚠️ prefix
6. **Record execution result:**
   ```
   add_agent_execution_result("cve_audit_date", "{YYYY-MM-DD}")
   add_agent_execution_result("cve_critical_count", "{n}")
   add_agent_execution_result("cve_high_count", "{n}")
   add_agent_execution_result("cve_total_count", "{n}")
   add_agent_execution_result("cve_audit_status", "PASS|WARN|FAIL")
   add_agent_execution_result("cve_audit_pr", "{pr_number}")
   add_agent_execution_result("cve_fix_prs", "{comma_separated_pr_numbers}")
   ```

---

## Error Handling

- If a CVE database is unreachable, retry 3 times with 10-second delays
- If a database remains unreachable, document the gap and proceed with available sources
- If a scanning tool fails to install, document and use alternative methods
- Never skip a dependency—if automated tools fail, perform manual lookup
- If `web_read` returns errors for CVE lookups, try alternative URL formats or databases
- If PR creation fails, retry once; if still failing, save report locally and alert
- If a fix breaks tests, create the PR as draft with a note about required manual intervention

---

## Execution Command

To run this audit, execute:

```
todo_reset [
  "Phase 0: Collect baseline from previous reports and open security PRs",
  "Phase 1: Scan repository and build complete dependency inventory",
  "Phase 2: Query CVE databases (NVD, GitHub Advisory, OSV) for all dependencies",
  "Phase 3: Run automated vulnerability scanners (govulncheck, npm audit, etc.)",
  "Phase 4: Analyze code patterns with ast-grep for security anti-patterns",
  "Phase 5: Review security-relevant configuration files",
  "Phase 6: Classify all findings by severity and determine exploitability",
  "Phase 7: Generate comprehensive audit report",
  "Phase 8: Submit audit report as PR",
  "Phase 9: Create remediation PRs for all Critical/High severity findings",
  "Phase 10: Record execution results and annotate critical findings"
]
```

Then proceed through each phase methodically, marking items complete as you go.
