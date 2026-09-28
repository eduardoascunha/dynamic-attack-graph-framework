# Master's Dissertation Project

This repository is organized into two top-level folders:

- **[`thesis/`](thesis/)** — The written dissertation (Typst source, images, bibliography, glossary).
- **[`src/`](src/)** — The complete code pipeline: an automated workflow that generates
  risk-scored attack graphs from environment descriptions, combining live threat
  intelligence, vulnerability correlation, and MulVAL-based attack graph reasoning.

## Getting started

The application and all of its orchestration live under `src/`:

```bash
cd src
make ingest         # run the full pipeline (default scenario)
```

See [`src/README.md`](src/README.md) for the full pipeline documentation, available
scenarios, and configuration details.

## Licensing

- `src/mulval/` contains MulVAL, licensed under GPL-3.0-or-later.
  Its original license and copyright notices are preserved.

- The material in `thesis/` is licensed under CC BY 4.0, except for third-party
  material identified in the dissertation.

- All remaining source code and files are Copyright © 2026 Eduardo André Silva Cunha.
  All rights reserved. No license is granted for their reuse.
