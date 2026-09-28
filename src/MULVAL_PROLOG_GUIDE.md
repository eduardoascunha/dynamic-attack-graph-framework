# MulVAL Prolog Guide

This guide explains how to build a MulVAL input `.P` file, what the main facts mean, and how that maps to the files in this repository.

## Goal

A MulVAL Prolog file describes:

- where the attacker starts
- which hosts can talk to which other hosts
- what software or services exist on each host
- what vulnerabilities exist
- what the attacker is trying to achieve

MulVAL then applies its rule set to derive attack paths.

## Minimal Structure

A practical scenario usually has these parts:

```prolog
/* attacker entry point */
attackerLocated(internet).

/* network reachability */
hacl(internet, webServer, tcp, 80).
hacl(workStation, internet, httpProtocol, httpPort).

/* installed software or exposed services */
installed(workStation, firefox).
networkServiceInfo(webServer, httpd, tcp, 80, apache).

/* vulnerabilities */
vulExists(workStation, 'CVE-2020-1234', firefox).
vulProperty('CVE-2020-1234', remoteClient, privEscalation).

vulExists(webServer, 'CVE-2021-41773', httpd).
vulProperty('CVE-2021-41773', remoteExploit, privEscalation).

/* user and behavior facts for client-side attacks */
hasAccount(alice, workStation, user).
inCompetent(alice).

/* attack goal */
attackGoal(execCode(workStation, _)).
attackGoal(execCode(webServer, _)).
```

## What The Main Facts Mean

### Entry point

```prolog
attackerLocated(internet).
```

The attacker starts from the logical location `internet`.

### Network reachability

```prolog
hacl(Source, Destination, Protocol, Port).
```

This means `Source` can reach `Destination` over the given protocol and port.

Examples:

```prolog
hacl(internet, webServer, tcp, 80).
hacl(workStation, internet, httpProtocol, httpPort).
```

These facts are often the difference between a reachable and unreachable exploit path.

### Installed client software

```prolog
installed(Host, Program).
```

Use this for software a user runs on a machine, such as browsers or document readers.

Example:

```prolog
installed(victim1, firefox).
```

### Exposed network service

```prolog
networkServiceInfo(Host, Program, Protocol, Port, RunAsUser).
```

Use this for server-side software that is exposed on the network.

Example:

```prolog
networkServiceInfo(webServer, httpd, tcp, 80, apache).
```

This is required for MulVAL to exploit a `remoteExploit` vulnerability against a service.

### Vulnerability presence

```prolog
vulExists(Host, VulnId, Program).
```

This says the vulnerable program exists on the host.

Example:

```prolog
vulExists(victim1, 'CVE-2020-15671', firefox).
```

### Vulnerability type and impact

```prolog
vulProperty(VulnId, ExploitType, Consequence).
```

This tells MulVAL how the vulnerability can be used.

Common exploit types:

- `remoteExploit`: attacker exploits a listening service remotely
- `remoteClient`: attacker exploits client software through malicious content
- `localExploit`: attacker already has execution on the host and escalates privileges

Common consequences:

- `privEscalation`: can lead to code execution or privilege gain
- `dos`: denial of service effect

Examples:

```prolog
vulProperty('CVE-2021-41773', remoteExploit, privEscalation).
vulProperty('CVE-2020-15671', remoteClient, privEscalation).
```

### User account on host

```prolog
hasAccount(Principal, Host, Permission).
```

This is needed for many client-side paths.

Example:

```prolog
hasAccount(victim1_user, victim1, user).
```

### User behavior

```prolog
inCompetent(Principal).
competent(Principal).
```

These facts drive whether a user is likely to open malicious content. In this rule set, client-side attacks typically need one of these.

Example:

```prolog
inCompetent(victim1_user).
```

### Attack goal

```prolog
attackGoal(execCode(Host, _)).
```

This is the state MulVAL tries to prove reachable.

Example:

```prolog
attackGoal(execCode(victim1, _)).
```

## How MulVAL Uses These Facts

### Server-side remote exploitation

MulVAL can derive code execution from a server vulnerability when all of these line up:

- `vulExists(Host, VulnId, Program)`
- `vulProperty(VulnId, remoteExploit, privEscalation)`
- `networkServiceInfo(Host, Program, Protocol, Port, User)`
- enough `hacl(...)` facts to give network access

If `networkServiceInfo(...)` is missing, `remoteExploit` usually does nothing.

### Client-side exploitation

MulVAL can derive code execution from a client vulnerability when all of these line up:

- `vulExists(Host, VulnId, Program)`
- `vulProperty(VulnId, remoteClient, privEscalation)`
- `hasAccount(Principal, Host, Perm)`
- `competent(Principal)` or `inCompetent(Principal)`
- enough reachability facts for malicious input to reach the host

If `hasAccount(...)` and user behavior facts are missing, `remoteClient` usually does nothing.

### Local privilege escalation

`localExploit` is not a good initial foothold. It usually only matters after MulVAL already proved `execCode(Host, SomePerm)` on the same host.

## How This Repository Builds `scenario.P`

The environment correlation layer reads:

- `asset_cpe_mapping.json`
- `stride_definition.json`
- a source `scenario*.P`

Then it generates a final `scenario.P` with vulnerability facts appended.

### `asset_cpe_mapping.json`

This maps repository assets to software names and CPEs.

Example:

```json
{
  "assets": [
    {
      "asset": "victim1",
      "client_software": [
        {
          "software_name": "firefox",
          "cpe": "cpe:2.3:a:mozilla:firefox:26:*:*:*:*:*:*:*"
        }
      ]
    }
  ]
}
```

That becomes facts like:

```prolog
vulExists(victim1, 'CVE-2020-15671', firefox).
vulProperty('CVE-2020-15671', remoteClient, privEscalation).
```

### `stride_definition.json`

This describes additional modeled threats.

Example:

```json
{
  "system": "scenario1",
  "assets": [
    {
      "name": "victim1",
      "service": "firefox"
    }
  ],
  "threats": [
    {
      "id": "T1",
      "stride": "Elevation of Privilege",
      "asset": "victim1",
      "impact": "remote_code_execution"
    }
  ]
}
```

Important meaning of `service` here:

- it becomes the third argument of generated `vulExists(asset, threat_name, service)`
- it should match the MulVAL program name you want the threat attached to
- for client-side threats, it should usually match the client software name from `asset_cpe_mapping.json`
- for server-side threats, it should usually match the exposed service name used in `networkServiceInfo(...)`

## Common Modeling Mistakes

### Vulnerabilities exist, but no attack path appears

Usually one of these is missing:

- `networkServiceInfo(...)` for a `remoteExploit`
- `hasAccount(...)` for a `remoteClient`
- `competent(...)` or `inCompetent(...)` for a `remoteClient`
- `hacl(...)` facts that make the target reachable

### `localExploit` is used for an initial compromise

That usually fails. `localExploit` is generally a follow-up step after initial execution.

### STRIDE asset `service` does not match the modeled program

If `stride_definition.json` uses a service name that does not match the actual program you modeled, the generated facts may be semantically wrong.

Bad example:

```json
{
  "name": "victim1",
  "service": "windows_2000"
}
```

when the actual vulnerable client software is `firefox`.

Better:

```json
{
  "name": "victim1",
  "service": "firefox"
}
```

## Practical Checklist

Before running MulVAL, check:

- each `attackGoal(...)` names a real host
- each vulnerable program name is consistent across files
- server-side vulnerabilities have `networkServiceInfo(...)`
- client-side vulnerabilities have `hasAccount(...)`
- client-side vulnerabilities have `competent(...)` or `inCompetent(...)`
- reachability is modeled with `hacl(...)`