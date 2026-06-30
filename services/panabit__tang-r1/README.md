# Panabit TANG-R1

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id panabit-tang-r1 ./services//panabit__tang-r1
```

## Behavior

- Put the Panabit endpoint and non-sensitive HTTP settings in config. Put `bindUser`/`bindPassword` or their aliases in `secret.schema.json`.
- `Login` maps to `GET /api/panabit.cgi/API` with `api_action=api_login`, caches a successful API token per OctoBus instance, and does not return the token or raw login body.
- `ListIPTable`, `AddIPTable`, `BlockIP`, and `UnblockIP` map to `POST /api/panabit.cgi` with multipart form data and use the cached token from `Login`. Deprecated request `api_token` fields are ignored.
- Business responses are passed through as device `code`, `msg`, and raw JSON struct fields.
- HTTP 401/403 map to `PERMISSION_DENIED`; other 4xx responses map to `FAILED_PRECONDITION`; 5xx and transport failures map to `UNAVAILABLE`.

Example config:

```json
{
  "restBaseUrl": "https://panabit.example.local",
  "timeoutMs": 1500,
  "skipTlsVerify": false
}
```

Example secret:

```json
{
  "bindUser": "api_user",
  "bindPassword": "replace-with-secret"
}
```

## Local Checks

```bash
cd services
npm run validate -- --service-dir panabit__tang-r1
npm test -- --service-dir panabit__tang-r1 --coverage
npm run pack:check
```
