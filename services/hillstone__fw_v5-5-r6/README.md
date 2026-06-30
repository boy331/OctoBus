# Hillstone FW V5.5R6

This package preserves legacy gRPC package and method names where applicable.

`Login` reads the management host from instance config and credentials from instance secret/config, caches the upstream session by OctoBus instance and host, and returns only `http_status`. Deprecated request cookie fields on address-group RPCs are ignored; create, update, and query use the cached session from a prior successful `Login`.

## Import

```bash
octobus service import --id hillstone-fw-v5-5-r6 ./services//hillstone__fw_v5-5-r6
```

## Local Checks

```bash
cd services
npm run validate -- --service-dir hillstone__fw_v5-5-r6
npm test -- --service-dir hillstone__fw_v5-5-r6 --coverage
npm run pack:check
```
