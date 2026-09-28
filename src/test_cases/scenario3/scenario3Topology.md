# Scenario 3 Topology — Enterprise Healthcare Patient Portal (HIS)

A larger, multi-tier hospital information system. An internet-facing HAProxy load
balancer terminates TLS and fronts an Apache Tomcat patient portal. The portal
calls an Eclipse Jetty REST API, which authenticates against a Keycloak identity
provider and is backed by a PostgreSQL records database, a Memcached session
cache and a RabbitMQ HL7 message broker. A back-office clinician workstation
reads external email.

```mermaid
%%{init: {"theme": "base", "themeVariables": {"background": "#ffffff", "fontSize": "18px"}}}%%
flowchart TB
    internet(["Internet\n(attacker located here)"])
   clinicianWorkstation["<b>Back Office</b><br/>clinicianWorkstation<br/>Thunderbird 149<br/>client"]
   reverseProxy["<b>DMZ</b><br/>reverseProxy<br/>HAProxy 3.2.6<br/>tcp/443"]
   portalServer["<b>Application Tier</b><br/>portalServer<br/>Apache Tomcat 10.0.27<br/>tcp/8080"]
   apiServer["<b>Application Tier</b><br/>apiServer<br/>Eclipse Jetty 12.1.7<br/>tcp/8443"]
   authServer["<b>Identity Tier</b><br/>authServer<br/>Keycloak 19.0.2<br/>tcp/9443"]
   dbServer["<b>Data Tier</b><br/>dbServer<br/>PostgreSQL 18.4<br/>tcp/5432"]
   cacheServer["<b>Data Tier</b><br/>cacheServer<br/>Memcached 1.6.22<br/>tcp/11211"]
   mqServer["<b>Data Tier</b><br/>mqServer<br/>RabbitMQ 3.7.20<br/>tcp/5672"]

    internet -->|"HTTPS:443"| reverseProxy
    reverseProxy -->|"TCP:8080"| portalServer
    portalServer -->|"TCP:8443"| apiServer
    apiServer -->|"TCP:9443"| authServer
    apiServer -->|"TCP:5432"| dbServer
    apiServer -->|"TCP:11211"| cacheServer
    apiServer -->|"TCP:5672"| mqServer
    clinicianWorkstation -->|"Email / browsing"| internet

    classDef cloud fill:#E7F2FF,stroke:#99b,color:#333
    classDef workstation fill:#F5F0FF,stroke:#a99bc5,color:#333
    classDef dmz fill:#FFF2E8,stroke:#cf9b72,color:#333
    classDef application fill:#EDF8F2,stroke:#82b896,color:#333
    classDef identity fill:#FFF7D9,stroke:#c7ad59,color:#333
    classDef data fill:#F3F5F8,stroke:#8fa3b8,color:#333

    class internet cloud
    class clinicianWorkstation workstation
    class reverseProxy dmz
    class portalServer,apiServer application
    class authServer identity
    class dbServer,cacheServer,mqServer data
```

| Element | Meaning |
|---|---|
| Internet | External attacker location |
| reverseProxy | Internet-facing HAProxy load balancer / TLS terminator (DMZ) |
| portalServer | Apache Tomcat patient-portal web application |
| apiServer | Eclipse Jetty REST API back-end |
| authServer | Keycloak single sign-on / identity provider |
| dbServer | PostgreSQL patient-records database |
| cacheServer | Memcached session / lookup cache |
| mqServer | RabbitMQ HL7 / clinical-event message broker |
| clinicianWorkstation | Back-office clinician host (email client) |
| Directed link | Allowed network reachability (`hacl`) |
| Attack goal | Desired MulVAL end state (`execCode`) |

## Attack path summary

1. The attacker reaches `reverseProxy` from the internet and exploits the HAProxy
   service (server-side, `remoteExploit`) to gain code execution in the DMZ.
2. From `reverseProxy` the attacker pivots to `portalServer` (Tomcat) and then to
   the `apiServer` (Jetty) REST back-end.
3. From `apiServer` the attacker fans out to the identity and data tiers:
   `authServer` (Keycloak), `dbServer` (PostgreSQL), `cacheServer` (Memcached)
   and `mqServer` (RabbitMQ).
4. In parallel, the `clinicianWorkstation` opens a malicious email attachment and
   its vulnerable mail client is exploited (client-side, `remoteClient`).
