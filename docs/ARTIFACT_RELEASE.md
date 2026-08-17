# Artifact Release Policy

The release is divided between the lightweight Git repository and an archival
artifact bundle. This keeps the code reviewable while respecting benchmark
licenses and avoiding large generated files in Git history.

## Main Git repository

The main branch contains:

- source code and tests;
- prompt and configuration specifications;
- metric implementations;
- documentation and expected artifact paths;
- small, license-safe examples.

## Archival artifact bundle

Subject to applicable licenses, an acceptance-stage archive is planned to
contain:

- dataset split identifiers and checksums;
- preprocessing and index metadata;
- frozen experiment configuration files;
- compact table-level metric summaries;
- paired clean/attack prediction identifiers and derived statistics;
- hashes that connect summaries to the corresponding artifacts.

The archive may be hosted through a versioned GitHub Release, Zenodo, OSF, or
institutional storage. Its persistent location and checksum should be added to
the main README when available.

## Not redistributed

The following are outside the public release unless their licenses explicitly
permit redistribution:

- raw third-party benchmark payloads;
- provider-controlled model weights or endpoints;
- API keys and private database credentials;
- unrestricted prompt/response logs containing licensed or sensitive data;
- disposable caches and development-only workspaces.

## Current availability

The GitHub repository provides the reference implementation and lightweight
verification materials. The matched archival bundle will extend this release
with table-level artifacts when licensing and distribution conditions permit.
The authors can handle verification requests for restricted or pending
artifacts during review.
