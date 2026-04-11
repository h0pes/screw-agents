# Phase 2 End-to-End Smoke Test Checklist

Manual integration test for Claude Code. Run after all code is merged.

## Prerequisites

1. MCP server configured in Claude Code:
   ```bash
   claude mcp add screw-agents -- uv run --directory /path/to/screw-agents python -m screw_agents.server
   ```
2. Subagent and skill files installed (or symlinked from `plugins/screw/`)
3. A test project with known-vulnerable code (use `benchmarks/fixtures/`)

## Test Cases

### TC-1: Individual agent scan (natural language)

- [ ] Open Claude Code in a project directory
- [ ] Say: "review benchmarks/fixtures/sqli/vulnerable/ for SQL injection"
- [ ] Verify: screw-review skill activates, delegates to screw-sqli subagent
- [ ] Verify: subagent calls scan_sqli MCP tool
- [ ] Verify: subagent presents findings conversationally
- [ ] Verify: `.screw/findings/sqli-*.json` and `.screw/findings/sqli-*.md` files created
- [ ] Verify: `.screw/.gitignore` created with correct content

### TC-2: Individual agent scan (slash command)

- [ ] Run: `/screw:scan sqli benchmarks/fixtures/sqli/vulnerable/`
- [ ] Verify: same pipeline as TC-1
- [ ] Verify: `--thoroughness deep` flag works

### TC-3: Domain scan

- [ ] Say: "review benchmarks/fixtures/sqli/vulnerable/ for injection vulnerabilities"
- [ ] Verify: screw-injection orchestrator dispatched
- [ ] Verify: all 4 agents analyzed (sqli, cmdi, ssti, xss findings in report)
- [ ] Verify: `.screw/findings/injection-*.md` written

### TC-4: Full review

- [ ] Say: "full security review of benchmarks/fixtures/"
- [ ] Verify: screw-full-review dispatched → screw-injection dispatched
- [ ] Verify: `.screw/findings/full-review-*.md` written

### TC-5: False positive recording

- [ ] Run a scan that produces findings
- [ ] Say: "finding #1 is a false positive because [reason]"
- [ ] Verify: subagent calls record_exclusion MCP tool
- [ ] Verify: `.screw/learning/exclusions.yaml` created/updated
- [ ] Verify: exclusion has correct id, agent, scope

### TC-6: Exclusion applied on re-scan

- [ ] Re-run the same scan from TC-5
- [ ] Verify: the excluded finding is annotated or suppressed
- [ ] Verify: markdown report includes "Suppressed Findings" section

### TC-7: Unavailable agent fallback

- [ ] Say: "check for SSRF vulnerabilities"
- [ ] Verify: skill responds with available agents, does not crash

### TC-8: format_output tool

- [ ] Verify: JSON format produces valid JSON array
- [ ] Verify: SARIF format produces valid SARIF 2.1.0
- [ ] Verify: Markdown format produces readable report

## Expected Results

All test cases should pass without errors. The MCP server should handle all tool calls. Subagent prompts should produce structured findings matching the Finding JSON schema.
