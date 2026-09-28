# Scenario 1 Topology

```mermaid
flowchart LR
    internet(["Internet\n(attacker located here)"])

    subgraph Scenario1["Internal Network"]
        victim1["victim1\nsoftware: firefox\nCPE: firefox 26\ngoal: execCode(victim1, _)"]
        victim2["victim2\nsoftware: dotnet_framework\nCPE: .NET Framework 4.5\ngoal: execCode(victim2, _)"]
        victim3["victim3\nsoftware: ie\nCPE: internet_explorer 7\ngoal: execCode(victim3, _)"]
    end

    victim1 -->|"HTTP browsing\nhacl(victim1, internet, httpProtocol, httpPort)"| internet
    victim2 -->|"HTTP browsing\nhacl(victim2, internet, httpProtocol, httpPort)"| internet
    victim3 -->|"HTTP browsing\nhacl(victim3, internet, httpProtocol, httpPort)"| internet

    classDef cloud fill:#E7F2FF,stroke:#99b,color:#333
    classDef host fill:#F8FBFF,stroke:#aac,color:#333

    class internet cloud
    class victim1,victim2,victim3 host
```

| Element | Meaning |
|---|---|
| Internet | External attacker location |
| victim1..3 | End-user hosts |
| Outgoing HTTP link | Host can access malicious content on the internet |
| Attack goal | Desired MulVAL end state |
