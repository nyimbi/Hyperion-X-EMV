# Hyperion Trace Pack Audit

- Kernel version: 0.1.0
- ABI version: 2
- Trace pack path: `docs/prelab_apdu_trace_pack.jsonl`
- Status: `prelab_fixture_reviewable`
- Boundary: trace-pack audit only; full lab/test-tool trace acceptance is still required before CERT-OPEN-012 can close
- Size bytes: 12154
- SHA-256: `e63c080e01a400262adfd4e05f5bf2be65fb8dfb5fe5b8834f8edefbd1d0d438`
- Line count: 45

## Cases
| Case | Metadata | Scenario | Identity | Commands | Responses | TLV Streams | Findings |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| `prelab.masking.generate-ac` | true | true | true | 3 / 3 | 3 / 3 | 0 / 0 | none |
| `prelab.masking.issuer-auth-script` | true | true | true | 2 / 2 | 2 / 2 | 1 / 1 | none |
| `prelab.masking.issuer-script-retry` | true | true | true | 2 / 2 | 2 / 2 | 0 / 0 | none |
| `prelab.masking.track2-record` | true | true | true | 1 / 1 | 1 / 1 | 0 / 0 | none |
| `prelab.masking.follow-up-status` | true | true | true | 4 / 4 | 4 / 4 | 0 / 0 | none |
| `prelab.masking.generate-ac-status-only` | true | true | true | 1 / 1 | 1 / 1 | 0 / 0 | none |
