#show raw: set block(
  fill: gray.lighten(80%),
  radius: 10pt,
  inset: 1.5em,
)

= Risk Scoring Configuration Reference <app-scoring>

The asset criticality factor $alpha$ multiplies the base risk in the path risk computation, so a value below $1.0$ dampens and a value above $1.0$ amplifies an asset's contribution to the score. It is selected from one of four named levels. @tab-criticality-levels lists the values applied throughout the evaluation.

#figure(
  table(
    columns: (1.5fr, 1fr, 2.5fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*Criticality level*], [*Factor $alpha$*], [*Effect on the path risk score*],
    ),
    [LOW], [0.4], [Strongly reduces the score],
    [MEDIUM (default)], [0.7], [Moderately reduces the score when no criticality is declared],
    [HIGH], [1.0], [Leaves the score unscaled],
    [CRITICAL], [1.3], [Amplifies the score],
  ),
  caption: [Asset criticality factor $alpha$ per named level.],
) <tab-criticality-levels>

The remaining global parameters, applied uniformly across all experiments unless explicitly overridden per asset, are summarized in @tab-global-scoring-parameters.

#figure(
  table(
    columns: (2.2fr, 1fr, 2.3fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*Parameter*], [*Value*], [*Role*],
    ),
    [KEV multiplier ($k_("KEV")$)], [1.5 / 1.0], [Amplifies vulnerabilities listed in CISA KEV and is neutral otherwise],
    [CIA multiplier ($k_("CIA")$)], [0.5-1.5], [Weights confidentiality, integrity and availability impact per asset priority and is neutral (1.0) when priorities are equal],
    [Top paths retained], [10], [Highest risk root-to-leaf paths kept in the summary report],
    [Maximum path depth], [30], [Bound on path enumeration and cycle guard],
    [Summary graph path cap], [200], [Highest risk paths aggregated into the host-level summary graph],
    [Default asset criticality], [MEDIUM], [Applied when an asset declares no explicit criticality],
  ),
  caption: [Global scoring and enumeration parameters.],
) <tab-global-scoring-parameters>

The CIA multiplier is interpreted relatively: when the confidentiality, integrity and availability priorities of an asset are equal, the weighted average collapses to a neutral value of $1.0$, so that impact prioritization only takes effect when an analyst deliberately favours one dimension over the others.

= STRIDE-to-MulVAL Mapping <app-stride>

As part of the environment correlation layer, each validated STRIDE threat is translated into MulVAL facts. This step is necessary because MulVAL reasons only over its own fixed vocabulary of `vulExists`/`vulProperty` facts, a small set of exploitation primitives and a small set of consequences. A STRIDE threat, being a qualitative category with a declared impact, carries no meaning to the engine on its own. The mapping therefore turns each threat into a synthetic vulnerability fact, selecting the exploitation primitive from the STRIDE category and the consequence from the declared impact according to @tab-stride-primitives and @tab-stride-consequences. This allows adversarial assumptions identified during threat modeling to participate in attack graph generation alongside vulnerability facts derived from CVEs, without changing MulVAL's interaction rules.

The mapping operationalizes the implementation and does not claim a universal semantic equivalence between STRIDE categories and MulVAL primitives. STRIDE identifies the security property under threat, whereas a MulVAL primitive selects a rule family with specific attack preconditions. The defaults in @tab-stride-primitives therefore represent the entry condition assumed for the case studies: categories modelled as attacks through a reachable service use `remoteExploit`, repudiation assumes an attacker has already obtained a local foothold and uses `localExploit`, and elevation of privilege is represented by the client-side rule family `remoteClient`, for which the handler supplies the required user-context facts. The purpose is to obtain a deterministic and inspectable translation into the limited MulVAL vocabulary. In an operational deployment, the primitive should instead be selected for each threat from its concrete attack vector and available preconditions, since the STRIDE category alone does not determine either of them.

#figure(
  table(
    columns: (2fr, 1.5fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*STRIDE category*], [*MulVAL exploit primitive*],
    ),
    [Spoofing], [`remoteExploit`],
    [Tampering], [`remoteExploit`],
    [Repudiation], [`localExploit`],
    [Information Disclosure], [`remoteExploit`],
    [Denial of Service], [`remoteExploit`],
    [Elevation of Privilege], [`remoteClient`],
  ),
  caption: [Default implementation mapping of STRIDE categories to MulVAL exploitation primitives. Unrecognized categories default to `remoteExploit`.],
) <tab-stride-primitives>

#figure(
  table(
    columns: (2fr, 1.5fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*Declared impact*], [*MulVAL consequence*],
    ),
    [`account_compromise`], [`privEscalation`],
    [`data_modification`], [`privEscalation`],
    [`log_tampering`], [`privEscalation`],
    [`data_exfiltration`], [`privEscalation`],
    [`privilege_escalation`], [`privEscalation`],
    [`unauthorized_access`], [`privEscalation`],
    [`remote_code_execution`], [`privEscalation`],
    [`arbitrary_code_execution`], [`privEscalation`],
    [`data_exposure`], [`privEscalation`],
    [`service_disruption`], [`dos`],
    [`availability_loss`], [`dos`],
    [`service_unavailability`], [`dos`],
  ),
  caption: [Default implementation mapping of declared threat impacts to MulVAL consequences. Unrecognized impacts default to `privEscalation`.],
) <tab-stride-consequences>

For a threat mapped to the `remoteClient` primitive, the base scenario may optionally include the minimal user-context facts (`inCompetent()` and `hasAccount()`) required by the corresponding client-side interaction rules. These facts are included only when the threat model assumes that the asset's user can be induced to interact with malicious content. The STRIDE handler itself emits the `vulExists()` and `vulProperty()` facts.

= Threat Intelligence Database Schema <app-schema>

@lst-threat-intel-schema reproduces the schema of the shared Threat Intelligence Database, organized around the CVE identifier as the principal key. It is provisioned automatically when the database container is initialized.

#figure(
  ```sql
  CREATE SCHEMA IF NOT EXISTS threat_intel;

  CREATE TABLE IF NOT EXISTS threat_intel.cves (
      cve_id             VARCHAR(50) PRIMARY KEY,
      published_date     TIMESTAMP,
      last_modified_date TIMESTAMP,
      cvss_score_3_1     FLOAT,
      cvss_vector_3_1    VARCHAR(200),
      created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS threat_intel.cve_cpe_mapping (
      cve_id VARCHAR(50),
      cpe    VARCHAR(300),
      PRIMARY KEY (cve_id, cpe),
      FOREIGN KEY (cve_id) REFERENCES threat_intel.cves(cve_id)
  );

  CREATE TABLE IF NOT EXISTS threat_intel.epss (
      cve_id          VARCHAR(50) PRIMARY KEY,
      epss_score      FLOAT,
      epss_percentile FLOAT,
      created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS threat_intel.kev (
      cve_id               VARCHAR(50) PRIMARY KEY,
      product              VARCHAR(200),
      date_added           DATE,
      known_ransomware_use BOOLEAN DEFAULT FALSE,
      created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  ```,
  caption: [Threat Intelligence Database schema (PostgreSQL).],
) <lst-threat-intel-schema>

= Representative Scenario Input Artifacts <app-artifacts>

To illustrate the inputs consumed by the pipeline, this section reproduces the artifacts of Scenario 1 (Client-Side Exposure). The asset-to-CPE mapping associates each asset and service with its CPE identifier and, optionally, its criticality and CIA priorities.

#figure(
  ```json
  {
    "assets": [
      {
        "asset": "victim1",
        "criticality": "HIGH",
        "cia_weights": {
          "confidentiality": "HIGH",
          "integrity": "MEDIUM",
          "availability": "LOW"
        },
        "client_software": [
          { "software_name": "firefox",
            "cpe": "cpe:2.3:a:mozilla:firefox:26:*:*:*:*:*:*:*" }
        ]
      },
      {
        "asset": "victim2",
        "criticality": "MEDIUM",
        "client_software": [
          { "software_name": "finereader",
            "cpe": "cpe:2.3:a:abbyy:finereader:10.0:-:pro:*:*:*:*:*" }
        ]
      },
      {
        "asset": "victim3",
        "client_software": [
          { "software_name": "mozilla_vpn",
            "cpe": "cpe:2.3:a:mozilla:vpn:2.3:*:*:*:*:*:*:*" }
        ]
      }
    ]
  }
  ```,
  caption: [Scenario 1 `asset_cpe_mapping.json`.],
)

The STRIDE threat model declares, for each asset, the threat category, impact and the corresponding MITRE ATT&CK technique.

#figure(
  ```json
  {
    "system": "scenario1",
    "assets": [
      { "name": "victim1", "service": "firefox" },
      { "name": "victim2", "service": "finereader" },
      { "name": "victim3", "service": "mozilla_vpn" }
    ],
    "threats": [
      {
        "id": "T1",
        "stride": "Elevation of Privilege",
        "asset": "victim1",
        "impact": "remote_code_execution",
        "description": "Remote exploitation of the vulnerable client software leads to code execution on victim1",
        "mitre_attack": "T1203 - Exploitation for Client Execution"
      }
    ]
  }
  ```,
  caption: [Scenario 1 `stride_definition.json` (one of three analogous threats shown).],
)

Finally, the enriched `scenario.P` combines the author-written base network description with the vulnerability facts that the environment correlation layer appends below it. In the base description, `attackerLocated` and `hacl` declare the attacker's location and the allowed network reachability, `installed` records the software on each host, the `inCompetent`/`hasAccount` pairs supply the user context required by the client-side rules, and `attackGoal` states the objectives. The correlation layer then appends one `vulExists`/`vulProperty` pair per matched vulnerability, drawn both from the CVEs correlated to each asset and from the STRIDE model (the `threat_*` facts).

#figure(
  ```prolog
  /* --- Base network description (author-written scenario1MV.P) --- */
  /* network connection */
  attackerLocated(internet).
  hacl(victim1, internet, httpProtocol, httpPort).
  hacl(victim2, internet, httpProtocol, httpPort).
  hacl(victim3, internet, httpProtocol, httpPort).
  installed(victim1, firefox).
  installed(victim2, finereader).
  installed(victim3, mozilla_vpn).
  /* users */
  inCompetent(victim1_user).
  hasAccount(victim1_user, victim1, user).
  inCompetent(victim2_user).
  hasAccount(victim2_user, victim2, user).
  inCompetent(victim3_user).
  hasAccount(victim3_user, victim3, user).
  /* attack goals */
  attackGoal(execCode(victim1, _)).
  attackGoal(execCode(victim2, _)).
  attackGoal(execCode(victim3, _)).
  /* --- Vulnerability facts appended by the environment correlation layer --- */
  /* (CVE-derived and STRIDE-derived) */
  vulExists(victim2,'CVE-2019-20383',finereader).
  vulProperty('CVE-2019-20383',remoteClient,privEscalation).
  vulProperty(threat_t2_elevation_of_privilege,remoteClient,privEscalation).
  vulExists(victim2,threat_t2_elevation_of_privilege,finereader).
  vulExists(victim3,'CVE-2022-0517',mozilla_vpn).
  vulProperty('CVE-2022-0517',remoteClient,privEscalation).
  vulProperty(threat_t3_elevation_of_privilege,remoteClient,privEscalation).
  vulExists(victim3,threat_t3_elevation_of_privilege,mozilla_vpn).
  vulProperty(threat_t1_elevation_of_privilege,remoteClient,privEscalation).
  vulExists(victim1,threat_t1_elevation_of_privilege,firefox).
  ```,
  caption: [Enriched MulVAL scenario (`scenario.P`) for Scenario 1.],
)

= STIX Campaign Object Example <app-stix-example>

As discussed in the background chapter, @stix expresses each threat intelligence object in JSON, so that objects can be linked to one another to form a coherent intelligence picture. The following snippet illustrates a STIX 2.1 Campaign object.

#figure(
  ```json
  {
      "type": "campaign",
      "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "spec_version": "2.1",
      "created": "2016-04-06T20:03:00.000Z",
      "modified": "2016-04-06T20:03:23.000Z",
      "name": "Green Group Attacks Against Finance",
      "description": "Campaign by Green Group against targets in the financial services sector."
  }
  ```,
  caption: [Example of a STIX 2.1 Campaign object #cite(<OASIS_STIX_INTRO26>).],
)

= Detailed Annotated Attack Graph Output <app-graphs>

The following figure presents the detailed annotated attack graph for Scenario 3, produced by the post-processing layer. It shows the MulVAL attack graph enriched with threat intelligence and node-level risk scores. The corresponding raw MulVAL graph is available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario3/gen_graph/AttackGraph.pdf")[original `AttackGraph.pdf`] in the project repository.

#page(flipped: true)[
  == Scenario 3: Enterprise Healthcare Information System

  #figure(
    image("images/scenario3_annotated_small.png", width: 100%),
    caption: [Scenario 3 annotated attack graph produced by the post-processing layer, with threat intelligence enrichment and per-node risk scores.],
  ) <fig-scenario3-annotated>
]

