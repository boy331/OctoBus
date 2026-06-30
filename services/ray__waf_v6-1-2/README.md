# RAY WAF V6.1.2

OctoBus service package for RAY WAF V6.1.2 blacklist APIs.

Service root: `services/ray__waf_v6-1-2`.

Import it into OctoBus with:

```bash
octobus service import --id ray-waf-v6-1-2 ./services//ray__waf_v6-1-2
```

## Configuration

Static connection details are provided through config. Put the login password in `secret.schema.json`:

```json
{
  "restBaseUrl": "http://127.0.0.1:18081",
  "user": "api_user",
  "skipTlsVerify": true
}
```

```json
{
  "password": "SuperSecret"
}
```

`host` and `baseUrl` are accepted as base URL aliases. `username` is accepted as a `user` alias.

## Methods

- `Login`: `GET /apicenter/login/?username=...&password=...`, caching the device `random` session token inside the OctoBus instance without returning it.
- `QueryBlacklist`: `GET /apicenter/?action=blacklist_query&username=...&random=...`.
- `BlockIP`: `POST /apicenter/?action=blacklist_update&username=...&random=...`.
- `UnblockIP`: `POST /apicenter/?action=blacklist_del&username=...&random=...`.

Call `Login` before query, block, and unblock. Deprecated request `random` fields are ignored.

## Request Examples

Block one IPv4:

```json
{
  "ip": "203.0.113.10"
}
```

Unblock by blacklist ID:

```json
{
  "ids": "6"
}
```

Errors map to legacy gRPC codes: `INVALID_ARGUMENT`, `PERMISSION_DENIED`, `FAILED_PRECONDITION`, `UNAVAILABLE`, and `UNKNOWN`.
