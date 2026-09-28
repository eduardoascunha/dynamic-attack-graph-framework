# Scenario 2 Topology — E-commerce Application (Magento)

A medium, multi-tier e-commerce deployment. An internet-facing nginx reverse
proxy fronts a Magento (Adobe Commerce) storefront, which is backed by a MariaDB
database and a Redis cache. A back-office admin workstation browses out to the
internet.

```mermaid
%%{init: {"theme": "base", "themeVariables": {"background": "#ffffff", "fontSize": "18px"}}}%%
flowchart TB
    internet(["Internet\n(attacker located here)"])
   adminWorkstation["<b>Back Office</b><br/>adminWorkstation<br/>Firefox ESR 140.9<br/>client"]
   webProxy["<b>DMZ</b><br/>webProxy<br/>nginx 1.23.1<br/>tcp/80"]
   appServer["<b>Application Tier</b><br/>appServer<br/>Adobe Commerce 2.4.8<br/>tcp/8080"]
   dbServer["<b>Data Tier</b><br/>dbServer<br/>MariaDB 10.11.7<br/>tcp/3306"]
   cacheServer["<b>Data Tier</b><br/>cacheServer<br/>Redis 8.2.3<br/>tcp/6379"]

    internet -->|"HTTP:80"| webProxy
    webProxy -->|"TCP:8080"| appServer
    appServer -->|"TCP:3306"| dbServer
    appServer -->|"TCP:6379"| cacheServer
    adminWorkstation -->|"HTTP browsing"| internet

    classDef cloud fill:#E7F2FF,stroke:#99b,color:#333
    classDef workstation fill:#F5F0FF,stroke:#a99bc5,color:#333
    classDef dmz fill:#FFF2E8,stroke:#cf9b72,color:#333
    classDef application fill:#EDF8F2,stroke:#82b896,color:#333
    classDef data fill:#F3F5F8,stroke:#8fa3b8,color:#333

    class internet cloud
    class adminWorkstation workstation
    class webProxy dmz
    class appServer application
    class dbServer,cacheServer data
```

| Element | Meaning |
|---|---|
| Internet | External attacker location |
| webProxy | Internet-facing nginx reverse proxy (DMZ) |
| appServer | Magento (Adobe Commerce) storefront application |
| dbServer | MariaDB backend database |
| cacheServer | Redis session / cache store |
| adminWorkstation | Back-office admin host (client-side browsing) |
| Directed link | Allowed network reachability (`hacl`) |
| Attack goal | Desired MulVAL end state (`execCode`) |

## Attack path summary

1. The attacker reaches `webProxy` from the internet and exploits the nginx
   service (server-side, `remoteExploit`) to gain code execution.
2. From `webProxy` the attacker pivots to `appServer` and exploits Magento.
3. From `appServer` the attacker reaches the `dbServer` (MariaDB) and
   `cacheServer` (Redis) backends.
4. In parallel, the `adminWorkstation` browses malicious content and its
   vulnerable browser is exploited (client-side, `remoteClient`).
