# Security Policy

## Reporting a Vulnerability

Fortress is a dual-use security tool. If you discover a security vulnerability, please:

1. **Do NOT** open a public issue
2. Email the maintainer or open a [private security advisory](https://github.com/hyson810/fortress/security/advisories/new)

We will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Scope

We accept reports for:
- Vulnerabilities in the detection pipeline (bypass, evasion)
- Remote code execution in any component
- Privilege escalation
- Authentication/authorization bypass in the API or MCP server
- Credential or secret exposure

## Out of Scope

- Theoretical attacks requiring physical access
- Vulnerabilities in third-party tools invoked by the fusion module (nmap, hydra, etc.)
- Social engineering

## Process

1. Report received → acknowledged within 48h
2. Investigation → initial assessment within 5 business days
3. Fix development → timeline communicated
4. Release → security advisory published with CVE if applicable

Thank you for helping keep Fortress and its users safe.
