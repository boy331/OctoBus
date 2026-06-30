# QIANXIN FW SecGate3600

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id qianxin-fw-secgate3600 ./services//qianxin__fw-secgate3600
```

## Behavior

- Configure `host` in instance config and `user`/`password` in instance secret. Legacy `LoginRequest.username`, `LoginRequest.password`, and `LogoutRequest.username` are deprecated and ignored for credentials.
- `Login` maps to `POST /v1.0/login` and caches the returned token plus cookies internally per engine instance and host.
- `UpdateAddressGroup` maps to `POST /v1.0/rest/`, requires a prior successful `Login`, and sends the normalized object-address payload as a JSON array.
- `Logout` maps to `POST /v1.0/out`, reuses the cached cookie header, and clears the cached session.
- Login and logout responses do not return token, cookies, raw login body, raw JSON, `Set-Cookie`, or `Authorization`. Retained raw/header proto fields are deprecated and returned empty.
- Device JSON responses are mapped even when the HTTP status is an upstream error; transport, empty-body, malformed JSON, and invalid schema errors return non-OK gRPC errors.

## Config And Secret

Config:

```json
{
  "host": "https://198.51.100.10:8443",
  "timeoutMs": 5000,
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
npm run validate -- --service-dir qianxin__fw-secgate3600
npm test -- --service-dir qianxin__fw-secgate3600 --coverage
npm run pack:check
```
