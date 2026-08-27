# Aegis-MCP — Diagrams

All diagrams are [Mermaid](https://mermaid.js.org/) and render directly on GitHub.
The topology diagram lives in the [README](../README.md); the enforcement flow inside
the gateway is also in the [design spec §6.2](superpowers/specs/2026-06-15-aegis-mcp-gateway-design.md).

## Use cases

Mermaid has no native use-case diagram type; this is the standard flowchart emulation
(actors outside, use-case ellipses inside the system boundary).

```mermaid
flowchart LR
    Agent(["🤖 AI Agent<br>(via MCP host)"])
    Human(["🧑 Human operator"])
    Down(["⚙️ Downstream MCP server"])

    subgraph Aegis["Aegis-MCP gateway"]
        UC1(["List permitted tools/resources<br>(filtered by active profile)"])
        UC2(["Call a permitted tool /<br>read a permitted resource"])
        UC3(["Request a profile switch<br>(aegis.set_profile)"])
        UC4(["Poll / apply an approval<br>(aegis.approval_status)"])
        UC5(["Approve or deny an escalation<br>(aegis approve / deny &lt;id&gt;)"])
        UC6(["Review the audit log"])
        UC7(["Serve namespaced tools<br>(server__tool)"])
    end

    Agent --> UC1
    Agent --> UC2
    Agent --> UC3
    Agent --> UC4
    Human --> UC5
    Human --> UC6
    UC2 --> Down
    UC7 --> Down
```

## Tool-call enforcement flow

Every `tools/call` (and `resources/read`) passes the single middleware chokepoint;
nothing reaches a downstream server without core authorization
([ADR 006](architecture/ADR_006_go_sdk_and_core_shell_split.md)).

```mermaid
sequenceDiagram
    autonumber
    participant H as AI Host
    participant G as Aegis gateway (shell)
    participant C as Pure core<br>(naming → enforcer)
    participant A as Audit log
    participant D as Downstream server

    H->>G: tools/call "filesystem__read_file"
    G->>C: resolve wire name, authorize against active profile
    alt capability allowed
        C-->>G: allow
        G->>A: {"decision":"allow", ...}
        G->>D: tools/call "read_file"
        D-->>G: result
        G-->>H: result (relayed)
    else capability not in profile
        C-->>G: deny
        G->>A: {"decision":"deny", ...}
        G-->>H: AEGIS_CAP_DENIED (structured error)
        Note over D: downstream never contacted
    end
```

## Profile switch with human approval (HITL)

Non-blocking by design ([ADR 003](architecture/ADR_003_non_blocking_hitl.md)); the
decision travels over a per-user unix socket
([ADR 008](architecture/ADR_008_approval_ipc_unix_socket.md)).

```mermaid
sequenceDiagram
    autonumber
    participant H as AI Host (agent)
    participant G as Aegis gateway
    participant T as stderr prompt
    participant U as Human
    participant CLI as aegis approve CLI

    H->>G: aegis.set_profile "deploy"
    alt target in allowed_transitions
        G-->>H: OK, active=deploy (audited: switch/agent)
    else escalation needs a human
        G->>T: "approval required: id=apr_1 …"
        G-->>H: AEGIS_PENDING_APPROVAL, approval=apr_1<br>(profile unchanged, call not held open)
        U->>CLI: aegis approve apr_1
        CLI->>G: "approve apr_1" (unix socket)
        G-->>CLI: ok
        H->>G: aegis.approval_status "apr_1"
        G-->>H: approved → profile now deploy<br>(audited: switch/human)
    end
```

## Approval lifecycle

Approvals are single-use and bound to the profile they were granted from
([ADR 003](architecture/ADR_003_non_blocking_hitl.md)).

```mermaid
stateDiagram-v2
    [*] --> pending: agent requests non-edge switch
    pending --> approved: aegis approve id
    pending --> denied: aegis deny id
    approved --> applied: aegis.approval_status<br>(only if active profile still matches origin)
    denied --> [*]
    applied --> [*]: switch applied, audited as human
    note right of approved
        single-use: a consumed or
        stale ticket cannot be replayed
    end note
```

## Profile transition graph (sample policy)

The graph from `testdata/aegis.yaml`: solid edges switch without approval; anything
else — including the dashed example — requires a human
([ADR 002](architecture/ADR_002_transition_graph_not_tiers.md)).

```mermaid
flowchart LR
    default["default<br>read-only filesystem"]
    review["code-review<br>+ github search, sonarqube"]
    deploy["deploy<br>+ github deploy"]

    default -- free transition --> review
    review -- free transition --> default
    review -- free transition --> deploy
    deploy -- free transition --> default
    default -.->|"requires human approval"| deploy
```
