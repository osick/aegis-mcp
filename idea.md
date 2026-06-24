# Marktlücke 1: Zero-Trust MCP Security Gateway

## Kontext & Akuter Bedarf: 
Das Model Context Protocol ist der De-facto-Standard für die Werkzeuganbindung von KI-Agenten, leidet jedoch unter strukturellen Defiziten des JSON-RPC 2.0 Standards. Die unregulierte Anbindung lokaler und entfernter MCP-Server ermöglicht Prompt Injections, Tool Poisoning, weitreichenden Token-Passthrough und Remote Command Execution (RCE). Es fehlt eine unternehmensweite, protokollspezifische Firewall.

## MVP-Skizze: "Aegis-MCP"

Aegis-MCP ist ein spezialisierter Reverse-Proxy-Server, der sich zwischen KI-Hosts (wie Claude Desktop oder Cursor) und sämtliche nachgelagerte MCP-Server schaltet. Geschrieben in Go, um maximale Performance und minimale Supply-Chain-Abhängigkeiten zu gewährleisten, erzwingt die Architektur ein striktes "Zero-Trust"-Modell.Die Kerninnovation liegt in der Implementierung von "Capability-Level Scopes". Anstatt einem MCP-Server pauschalen Lese- oder Schreibzugriff zu gewähren, definiert Aegis-MCP granulare Berechtigungen, die bei jeder Transaktion validiert werden. Wildcard-Scopes werden kategorisch blockiert. Zur Lösung des Token-Passthrough-Problems implementiert das MVP den OAuth 2.1 Standard mit zwingendem PKCE (Proof Key for Code Exchange), wodurch serverseitige Zustandsvalidierungen sichergestellt werden. Zudem werden die MCP-Server auf Host-Ebene durch Kernel-Technologien wie seccomp (Linux) oder Seatbelt (macOS) in isolierte Sandboxes gezwungen, die jeglichen ausgehenden DNS-Traffic, der nicht für die Funktion des Tools essenziell ist, unterbinden. Der Go-to-Market-Ansatz fokussiert sich auf DevSecOps-Teams in großen Technologieunternehmen, wobei ein Freemium-Modell für den Open-Source-Kern eine schnelle Adoption sichert, während Enterprise-Dashboards für Audit-Logging monetarisiert werden.

* Der mcp server soll auch kontextbezogen tools und zugriffe filtern können (z.B. sonarqube mcp nur bei code review etc...)


* Input von Anthropic: https://cdn.prod.website-files.com/6889473510b50328dbb70ae6/6a1611a04085d7cd3dadc924_Claude-eBook-Zero-Trust-for-AI-Agents-05182026.pdf
