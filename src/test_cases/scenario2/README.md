# Scenario 2

This scenario models a medium, multi-tier e-commerce deployment. An internet-facing nginx reverse proxy fronts a Magento (Adobe Commerce) storefront, backed by a MariaDB database and a Redis cache, with a back-office admin workstation browsing out to the internet.

- `webProxy` runs `nginx`
- `appServer` runs `magento`
- `dbServer` runs `mariadb`
- `cacheServer` runs `redis`
- `adminWorkstation` uses `firefox`

The idea is to start from a simple MulVAL scenario, enrich it with vulnerability data from CPE to CVE correlation, add optional STRIDE threat-model facts, and then generate an attack graph.

## Topology

![Scenario 2 topology](scenario2Topology.svg)

## Folders

### `enviroment/`

This folder contains the scenario inputs and the generated scenario files.

- `scenario2MV.P`: the base MulVAL scenario written by hand
- `asset_cpe_mapping.json`: maps each asset to its software CPE
- `stride_definition.json`: optional STRIDE threat model for the scenario
- `scenario.P`: generated final scenario used as MulVAL input after correlation
- `registry/`: archived older versions of generated `scenario.P`

### `gen_graph/`

This folder contains files produced by MulVAL when the attack graph is generated.

- `AttackGraph.*`: graph outputs in different formats such as PDF, XML, DOT, and TXT
- `VERTICES.CSV` and `ARCS.CSV`: graph nodes and edges in CSV format

### `post_processing/`

This folder is used for any files created after MulVAL generation, such as processed graph outputs or annotations.
