# Huawei FW USG6000E

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id huawei-fw-usg6000e ./services//huawei__fw-usg6000e
```

## Behavior

`UpdateAddressGroup` performs one HTTPS `PUT` to replace a Huawei USG6000E address group with the requested full IPv4/IPv6 set. Empty `ipv4_list` and `ipv6_list` clear the group. Preview metadata (`preview_only`, `previewOnly`, `x-preview-only`, or `dry_run_preview`) returns status metadata without calling the upstream device.

Instance `config` supplies `host` and optional defaults such as `device_name`, `book_name`, timeout, TLS, and headers. Instance `secret` supplies `user` or `username` and `password`; deprecated request fields `host`, `user`, and `password` are ignored by the handler. Responses and error details do not include upstream raw bodies, request headers, request body, or credentials.

## Local Checks

```bash
cd services
npm run validate -- --service-dir huawei__fw-usg6000e
npm test -- --service-dir huawei__fw-usg6000e --coverage
npm run pack:check
```
