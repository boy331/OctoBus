# NSFOCUS NIPS V5.6R11

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id nsfocus-nips-v5-6-r11 ./services//nsfocus__nips_v5-6-r11
```

## Behavior

- Configure `host` in instance config and `user`/`password` in instance secret. Legacy `LoginRequest.username` and `LoginRequest.password` are deprecated and ignored.
- `Login` maps to `POST /api/system/account/login/login` and caches cookie, `api_key`, and `security_key` internally per instance.
- `BlockIP`, `ListBlacklist`, `UnblockByIds`, and `ApplyConfig` require a prior `Login`.
- Signed query parameters are generated from `security_key`, `api_key`, timestamp, and REST URI.
- Login responses do not return cookie, `api_key`, `security_key`, raw login body, or raw JSON. Retained raw response proto fields are deprecated and returned empty.
- Any HTTP response with a non-empty JSON body returns gRPC OK with mapped status and message; transport, empty-body, and JSON parsing errors return non-OK gRPC errors.

## Config And Secret

Config:

```json
{
  "host": "https://198.51.100.10:8443",
  "timeoutMs": 1500,
  "skipTlsVerify": false
}
```

Secret:

```json
{
  "user": "api_user",
  "password": "REDACTED"
}
```

## Local Checks

```bash
cd services
npm run validate -- --service-dir nsfocus__nips_v5-6-r11
npm test -- --service-dir nsfocus__nips_v5-6-r11 --coverage
npm run pack:check
```
