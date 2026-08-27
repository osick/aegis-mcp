# Security Policy

Aegis-MCP is a security tool; reports about its own security are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security-relevant bugs (policy bypass,
traversal, tool shadowing, approval replay, audit evasion, …).

Instead, use **GitHub's private vulnerability reporting** on this repository
("Security" tab → "Report a vulnerability"). You will get an initial response
within 7 days.

## Scope

In scope: anything that lets an agent or downstream server act outside the
active profile — capability or resource bypass, self-elevation without an
approved transition, approval replay, name spoofing/shadowing, or silent
(unaudited) denials/switches.

Out of scope: vulnerabilities in downstream MCP servers themselves, and
prompt-injection content *inside* allowed resources (content inspection is on
the roadmap, see README).

## Supported versions

Pre-1.0: only the latest release/`master` receives fixes.
