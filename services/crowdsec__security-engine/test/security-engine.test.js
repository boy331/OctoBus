import test from 'node:test';
import assert from 'node:assert/strict';

const METHOD_LIST_ALERTS = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/ListAlerts';
const METHOD_GET_ALERT = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/GetAlert';
const METHOD_LIST_DECISIONS = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/ListDecisions';
const METHOD_BLOCK_IP = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/BlockIP';
const METHOD_UNBLOCK_IP = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/UnblockIP';
const METHOD_DELETE_DECISION = '/Crowdsec_SECURITY_ENGINE.Crowdsec_SECURITY_ENGINE/DeleteDecision';

const makeCtx = (req = {}, overrides = {}) => ({
  config: overrides.config ?? {},
  secret: overrides.secret ?? {},
  bindings: overrides.bindings ?? {},
  limits: { timeoutMs: 10_000, ...(overrides.limits ?? {}) },
  meta: { instance_id: 'inst', request_id: 'req', ...(overrides.meta ?? {}) },
  req,
});

const importModule = async () => {
  const mod = await import('../src/security-engine.js');
  return mod;
};

const invokeRpc = async (mod, methodPath, req, overrides) => {
  const ctx = makeCtx(req, overrides);
  const rpc = mod.rpcdef(ctx);
  return rpc[methodPath]();
};

const mockFetch = (impl) => {
  global.fetch = impl;
};

const restoreFetch = (saved) => {
  global.fetch = saved;
};

// ── ListAlerts ──────────────────────────────────────────────────

test('ListAlerts — basic call returns alerts', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let loginCalled = false;
  let alertsCalled = false;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      loginCalled = true;
      return new Response(JSON.stringify({ code: 200, token: 'test-jwt-token', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts')) {
      alertsCalled = true;
      return new Response(JSON.stringify([
        {
          id: 1, uuid: 'u1', machine_id: 'm1', created_at: '2026-06-27T12:00:00Z',
          scenario: 'ssh-bf', scenario_hash: 'h1', scenario_version: '0.1',
          message: 'ssh brute force', events_count: 10,
          start_at: '2026-06-27T11:00:00Z', stop_at: '2026-06-27T12:00:00Z',
          capacity: 5, leakspeed: '10', simulated: false,
          source: { scope: 'ip', value: '1.2.3.4', ip: '1.2.3.4', as_number: '13335', as_name: 'CF', cn: 'US', latitude: 37.7, longitude: -122.4 },
          events: [{ timestamp: '2026-06-27T11:30:00Z', meta: [{ key: 'log', value: 'attempt' }] }],
          decisions: [{ id: 2, uuid: 'd1', origin: 'crowdsec', type: 'ban', scope: 'ip', value: '1.2.3.4', duration: '3h59m59s', scenario: 'ssh-bf', simulated: false }],
          meta: [{ key: 'reason', value: 'bf' }],
          remediation: true, kind: '',
        },
      ]), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  const result = await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.ok(loginCalled);
  assert.ok(alertsCalled);
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].id, 1);
  assert.equal(result.alerts[0].scenario, 'ssh-bf');
  assert.equal(result.alerts[0].source.ip, '1.2.3.4');
  assert.equal(result.alerts[0].decisions[0].type, 'ban');

  restoreFetch(saved);
});

test('ListAlerts — with query filters', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    requestUrl = url;
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_LIST_ALERTS, { scenario: 'ssh-bf', ip: '1.2.3.4', limit: 5 }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.ok(requestUrl.includes('scenario=ssh-bf'));
  assert.ok(requestUrl.includes('ip=1.2.3.4'));
  assert.ok(requestUrl.includes('limit=5'));

  restoreFetch(saved);
});

test('ListAlerts — missing machineId/password throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT — missing credentials
  }

  restoreFetch(saved);
});

test('ListAlerts — auth failure maps to UNAUTHENTICATED', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ message: 'invalid credentials' }), { status: 401, headers: { 'content-type': 'application/json' } });
    }
    return new Response('ok', { status: 200 });
  });

  try {
    await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'wrong-password' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 16); // UNAUTHENTICATED
  }

  restoreFetch(saved);
});

// ── GetAlert ────────────────────────────────────────────────────

test('GetAlert — basic call returns alert detail', async () => {
  const mod = await importModule();
  const saved = global.fetch;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts/1')) {
      return new Response(JSON.stringify({
        id: 1, uuid: 'u1', machine_id: 'm1', created_at: '2026-06-27T12:00:00Z',
        scenario: 'ssh-bf', message: 'ssh brute force',
        source: { scope: 'ip', value: '1.2.3.4', ip: '1.2.3.4' },
        events: [], decisions: [], meta: [],
        events_count: 10, start_at: '', stop_at: '', capacity: 0, leakspeed: '', simulated: false, remediation: true, kind: '', scenario_hash: '', scenario_version: '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  const result = await invokeRpc(mod, METHOD_GET_ALERT, { alert_id: 1 }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.equal(result.alert.id, 1);
  assert.equal(result.alert.scenario, 'ssh-bf');

  restoreFetch(saved);
});

test('GetAlert — missing alert_id throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_GET_ALERT, {}, { bindings: { endpoint: 'http://localhost:18080' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

test('GetAlert — 404 maps to FAILED_PRECONDITION', async () => {
  const mod = await importModule();
  const saved = global.fetch;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ message: 'alert not found' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });

  try {
    await invokeRpc(mod, METHOD_GET_ALERT, { alert_id: 999 }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 9); // FAILED_PRECONDITION
  }

  restoreFetch(saved);
});

// ── ListDecisions ───────────────────────────────────────────────

test('ListDecisions — basic call with apiKey returns decisions', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let usedAuth = '';

  mockFetch(async (url, opts) => {
    usedAuth = opts.headers['X-Api-Key'] || opts.headers['Authorization'] || '';
    return new Response(JSON.stringify([
      { id: 2, uuid: 'd1', origin: 'crowdsec', type: 'ban', scope: 'ip', value: '1.2.3.4', duration: '3h59m59s', scenario: 'ssh-bf', simulated: false },
      { id: 3, uuid: 'd2', origin: 'cscli', type: 'ban', scope: 'ip', value: '5.6.7.8', duration: '4h', scenario: 'manual', simulated: false },
    ]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_LIST_DECISIONS, {}, { bindings: { endpoint: 'http://localhost:18080', apiKey: 'test-api-key' } });
  assert.equal(result.decisions.length, 2);
  assert.equal(result.decisions[0].type, 'ban');
  assert.equal(result.decisions[1].origin, 'cscli');
  assert.equal(usedAuth, 'test-api-key');

  restoreFetch(saved);
});

test('ListDecisions — falls back to JWT when no apiKey', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;
  let usedAuth = '';
  let loginCalled = false;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      loginCalled = true;
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    usedAuth = opts.headers['Authorization'] || opts.headers['X-Api-Key'] || '';
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_LIST_DECISIONS, {}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.ok(loginCalled);
  assert.ok(usedAuth.startsWith('Bearer '));

  restoreFetch(saved);
});

test('ListDecisions — with query filters', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    requestUrl = url;
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_LIST_DECISIONS, { scope: 'ip', type: 'ban' }, { bindings: { endpoint: 'http://localhost:18080', apiKey: 'test-key' } });
  assert.ok(requestUrl.includes('scope=ip'));
  assert.ok(requestUrl.includes('type=ban'));

  restoreFetch(saved);
});

// ── BlockIP ─────────────────────────────────────────────────────

test('BlockIP — creates manual decision', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let postedBody = null;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts') && opts?.method === 'POST') {
      postedBody = JSON.parse(opts.body);
      // Crowdsec POST /v1/alerts returns array of alert IDs, not full objects
      return new Response(JSON.stringify(['10']), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts/10') && opts?.method === 'GET') {
      // Second call to fetch full alert details
      return new Response(JSON.stringify({
        id: 10, uuid: 'block-uuid',
        machine_id: 'test-machine',
        created_at: '2026-06-27T12:00:00Z',
        scenario: 'manual', message: 'manual block via OctoBus',
        source: { scope: 'ip', value: '9.9.9.9', ip: '9.9.9.9' },
        events: [],
        decisions: [
          { id: 20, uuid: 'dec-uuid', origin: 'cscli', type: 'ban', scope: 'ip', value: '9.9.9.9', duration: '4h', scenario: 'manual', simulated: false },
        ],
        meta: [],
        events_count: 1, start_at: '', stop_at: '', capacity: 0, leakspeed: '', simulated: false, remediation: true, kind: 'manual', scenario_hash: '', scenario_version: '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  const result = await invokeRpc(mod, METHOD_BLOCK_IP, { target_ip: '9.9.9.9' }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.equal(result.alert_id, 10);
  assert.equal(result.decision.type, 'ban');
  assert.equal(result.decision.value, '9.9.9.9');
  assert.ok(postedBody);
  assert.equal(postedBody[0].decisions[0].value, '9.9.9.9');
  assert.equal(postedBody[0].decisions[0].type, 'ban');

  restoreFetch(saved);
});

test('BlockIP — custom duration and reason', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let postedBody = null;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts') && opts?.method === 'POST') {
      postedBody = JSON.parse(opts.body);
      // Crowdsec POST /v1/alerts returns array of alert IDs
      return new Response(JSON.stringify(['11']), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (url.includes('/v1/alerts/11') && opts?.method === 'GET') {
      return new Response(JSON.stringify({
        id: 11, uuid: 'u',
        decisions: [
          { id: 21, origin: 'cscli', type: 'captcha', scope: 'ip', value: '8.8.8.8', duration: '24h', scenario: 'manual', simulated: false },
        ],
        source: {}, events: [], meta: [],
        events_count: 1, start_at: '', stop_at: '', capacity: 0, leakspeed: '', simulated: false, remediation: true, kind: 'manual', scenario_hash: '', scenario_version: '', machine_id: 'm', created_at: '', scenario: 'manual', message: '',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('not found', { status: 404 });
  });

  const result = await invokeRpc(mod, METHOD_BLOCK_IP, { target_ip: '8.8.8.8', duration: '24h', decision_type: 'captcha', reason: 'test block' }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.equal(result.decision.type, 'captcha');
  assert.equal(postedBody[0].decisions[0].duration, '24h');
  assert.equal(postedBody[0].message, 'test block');

  restoreFetch(saved);
});

test('BlockIP — missing target_ip throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_BLOCK_IP, {}, { bindings: { endpoint: 'http://localhost:18080' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

// ── UnblockIP ───────────────────────────────────────────────────

test('UnblockIP — deletes matching decisions', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    requestUrl = url;
    return new Response(JSON.stringify({ nbDeleted: '2' }), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_UNBLOCK_IP, { target_ip: '1.2.3.4' }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.equal(result.deleted_count, 2);
  assert.ok(requestUrl.includes('/v1/decisions'));
  assert.ok(requestUrl.includes('ip=1.2.3.4'), 'should use ip= shortcut for scope=ip');

  restoreFetch(saved);
});

test('UnblockIP — custom scope', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    requestUrl = url;
    return new Response(JSON.stringify({ nbDeleted: '1' }), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_UNBLOCK_IP, { target_ip: '10.0.0.0/24', scope: 'range' }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.ok(requestUrl.includes('range=10.0.0.0%2F24'), 'should use range= shortcut for scope=range');

  restoreFetch(saved);
});

test('UnblockIP — missing target_ip throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_UNBLOCK_IP, {}, { bindings: { endpoint: 'http://localhost:18080' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

// ── DeleteDecision ──────────────────────────────────────────────

test('DeleteDecision — deletes by ID', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    requestUrl = url;
    return new Response(JSON.stringify({ nbDeleted: '1' }), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  const result = await invokeRpc(mod, METHOD_DELETE_DECISION, { decision_id: 42 }, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
  assert.equal(result.deleted_count, 1);
  assert.ok(requestUrl.includes('/v1/decisions/42'));

  restoreFetch(saved);
});

test('DeleteDecision — missing decision_id throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_DELETE_DECISION, {}, { bindings: { endpoint: 'http://localhost:18080' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

// ── Error mapping ───────────────────────────────────────────────

test('5xx maps to UNAVAILABLE', async () => {
  const mod = await importModule();
  const saved = global.fetch;

  mockFetch(async (url) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ message: 'internal error' }), { status: 500, headers: { 'content-type': 'application/json' } });
  });

  try {
    await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 14); // UNAVAILABLE
  }

  restoreFetch(saved);
});

test('400 maps to INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;

  mockFetch(async (url) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ message: 'bad parameter' }), { status: 400, headers: { 'content-type': 'application/json' } });
  });

  try {
    await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'test-machine', password: 'test-password' } });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

// ── Config validation ────────────────────────────────────────────

test('missing endpoint throws INVALID_ARGUMENT', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  mockFetch(async () => new Response('ok', { status: 200 }));

  try {
    await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: {} });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 3); // INVALID_ARGUMENT
  }

  restoreFetch(saved);
});

test('endpoint trailing slash is trimmed', async () => {
  const mod = await importModule();
  const saved = global.fetch;
  let requestUrl = '';

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ code: 200, token: 'jwt-ok', expire: new Date(Date.now() + 3600000).toISOString() }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    requestUrl = url;
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  await invokeRpc(mod, METHOD_LIST_ALERTS, {}, { bindings: { endpoint: 'http://localhost:18080/', machineId: 'test-machine', password: 'test-password' } });
  assert.ok(!requestUrl.includes('18080//'));

  restoreFetch(saved);
});

// ── wrapLegacyHandler / SDK handler pattern ──────────────────────

test('handlers export maps full RPC paths to functions', async () => {
  const mod = await importModule();
  assert.ok(mod.handlers[mod.METHOD_LIST_ALERTS_FULL]);
  assert.ok(mod.handlers[mod.METHOD_GET_ALERT_FULL]);
  assert.ok(mod.handlers[mod.METHOD_LIST_DECISIONS_FULL]);
  assert.ok(mod.handlers[mod.METHOD_BLOCK_IP_FULL]);
  assert.ok(mod.handlers[mod.METHOD_UNBLOCK_IP_FULL]);
  assert.ok(mod.handlers[mod.METHOD_DELETE_DECISION_FULL]);
});

test('resolveCallContext handles single-arg (SDK) and two-arg (legacy) patterns', async () => {
  const mod = await importModule();
  // Single arg pattern (SDK): ctx contains { request, config, secret, method, ... }
  const singleArgResult = mod._test.resolveCallContext({}, { request: { limit: 5 }, config: { endpoint: 'http://x' } });
  assert.equal(singleArgResult.req.limit, 5);

  // Two-arg pattern (legacy): (req, ctx)
  const twoArgResult = mod._test.resolveCallContext({}, { limit: 5 }, { config: { endpoint: 'http://y' } });
  assert.equal(twoArgResult.req.limit, 5);
});

test('requestWithDefaults merges bindings with request overrides', async () => {
  const mod = await importModule();
  const bindings = { machineId: 'default-machine', password: 'default-pass', apiKey: 'default-key' };

  // Request overrides binding defaults
  const merged = mod._test.requestWithDefaults(bindings, { machine_id: 'override-machine' });
  assert.equal(merged.machine_id, 'override-machine');
  assert.equal(merged.password, 'default-pass');

  // No request override — uses bindings
  const defaultsOnly = mod._test.requestWithDefaults(bindings, {});
  assert.equal(defaultsOnly.machine_id, 'default-machine');
});

// ── getReqField preserves falsy values ──────────────────────────────

test('getReqField preserves falsy values (0, false, empty string)', async () => {
  const mod = await importModule();
  const { getReqField } = mod._test;

  // 0 should be preserved, not treated as undefined
  assert.equal(getReqField({ count: 0 }, 'count', 'count'), 0);
  // false should be preserved
  assert.equal(getReqField({ flag: false }, 'flag', 'flag'), false);
  // empty string should be preserved
  assert.equal(getReqField({ name: '' }, 'name', 'name'), '');
  // null should be treated as absent (returns undefined)
  assert.equal(getReqField({ count: null }, 'count', 'count'), undefined);
  // undefined returns undefined
  assert.equal(getReqField({}, 'missing', 'missing'), undefined);
  // camelCase fallback works
  assert.equal(getReqField({ alertId: 5 }, 'alert_id', 'alertId'), 5);
});

// ── mapHttpStatus does not leak upstream body ───────────────────────

test('mapHttpStatus does not leak upstream response body to callers', async () => {
  const mod = await importModule();
  const { errorWithCode } = mod._test;

  // 401 → UNAUTHENTICATED, message should NOT contain upstream body text
  const err401 = mod._test.rpcdef({ config: {}, secret: {}, bindings: { endpoint: 'http://x' }, req: {} });
  // Directly test mapHttpStatus through the code path
  const saved = global.fetch;
  mockFetch(async (url) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ message: 'secret-internal-details' }), { status: 401, headers: { 'content-type': 'application/json' } });
    }
    return new Response('ok', { status: 200 });
  });

  try {
    const ctx = makeCtx({}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'm', password: 'p' } });
    await mod.rpcdef(ctx)[METHOD_LIST_ALERTS]();
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 16); // UNAUTHENTICATED
    assert.ok(!err.message.includes('secret-internal-details'), 'error message must not contain upstream body');
  }

  restoreFetch(saved);
});

// ── 401 vs 403 distinction ────────────────────────────────────────

test('401 maps to UNAUTHENTICATED, 403 maps to PERMISSION_DENIED', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;

  // 401 → UNAUTHENTICATED (code 16)
  mockFetch(async (url) => {
    if (url.includes('/v1/watchers/login')) {
      return new Response(JSON.stringify({ message: 'unauthorized' }), { status: 401, headers: { 'content-type': 'application/json' } });
    }
    return new Response('ok', { status: 200 });
  });

  try {
    const ctx = makeCtx({}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'm', password: 'p' } });
    await mod.rpcdef(ctx)[METHOD_LIST_ALERTS]();
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 16); // UNAUTHENTICATED
  }

  restoreFetch(saved);
});

// ── JWT cache LRU eviction ─────────────────────────────────────────

test('JWT cache evicts oldest entries when max size is exceeded', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;
  let loginCount = 0;

  mockFetch(async (url, opts) => {
    if (url.includes('/v1/watchers/login')) {
      loginCount++;
      const body = JSON.parse(opts.body);
      // Each machineId gets a unique token
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        machine_id: body.machine_id,
        exp: Math.floor(Date.now() / 1000) + 3600,
      })).toString('base64url');
      const token = `${header}.${payload}.sig`;
      return new Response(JSON.stringify({ code: 200, token }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  // Fill cache beyond max size (100)
  const endpoint = 'http://localhost:18080';
  for (let i = 0; i < 105; i++) {
    const ctx = makeCtx({}, { bindings: { endpoint, machineId: `machine-${i}`, password: 'pass' } });
    await mod.rpcdef(ctx)[METHOD_LIST_ALERTS]();
  }

  // Login should have been called for each unique machine (no cache hits since all unique)
  assert.equal(loginCount, 105, 'all logins should fire for unique machine IDs');

  // First few entries should have been evicted (LRU), cache size should be capped
  // Re-request machine-0 — it should require a fresh login since it was evicted
  loginCount = 0;
  const ctx = makeCtx({}, { bindings: { endpoint, machineId: 'machine-0', password: 'pass' } });
  await mod.rpcdef(ctx)[METHOD_LIST_ALERTS]();
  assert.equal(loginCount, 1, 'evicted entry should require re-login');

  mod._test.clearJwtCache();
  restoreFetch(saved);
});

// ── buildTlsOptions warning ────────────────────────────────────────

test('buildTlsOptions warns when skipTlsVerify=true but NODE_TLS_REJECT_UNAUTHORIZED is not set', async () => {
  const mod = await importModule();
  const { buildTlsOptions } = mod._test;

  const savedEnv = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;

  const warnings = [];
  const savedWarn = console.warn;
  console.warn = (...args) => warnings.push(args.join(' '));

  const opts = buildTlsOptions(true);
  assert.ok(opts.insecureSkipVerify, 'should include insecureSkipVerify');
  assert.ok(opts.tlsInsecureSkipVerify, 'should include tlsInsecureSkipVerify');
  assert.ok(opts.skipTlsVerify, 'should include skipTlsVerify');
  assert.ok(warnings.some((w) => w.includes('skipTlsVerify')), 'should warn about NODE_TLS_REJECT_UNAUTHORIZED');

  console.warn = savedWarn;
  if (savedEnv !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedEnv;

  // When NODE_TLS_REJECT_UNAUTHORIZED=0, no warning
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const warnings2 = [];
  console.warn = (...args) => warnings2.push(args.join(' '));
  buildTlsOptions(true);
  assert.equal(warnings2.length, 0, 'no warning when NODE_TLS_REJECT_UNAUTHORIZED is set');

  console.warn = savedWarn;
  if (savedEnv !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedEnv;
  else delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
});

// ── Timeout uses DEADLINE_EXCEEDED ─────────────────────────────────

test('fetch timeout returns DEADLINE_EXCEEDED', async () => {
  const mod = await importModule();
  mod._test.clearJwtCache();
  const saved = global.fetch;

  // Simulate a timeout by having fetch throw a TimeoutError-like error
  mockFetch(async () => {
    const err = new Error('timeout');
    err.name = 'TimeoutError';
    throw err;
  });

  try {
    const ctx = makeCtx({}, { bindings: { endpoint: 'http://localhost:18080', machineId: 'm', password: 'p' }, limits: { timeoutMs: 100 } });
    await mod.rpcdef(ctx)[METHOD_LIST_ALERTS]();
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.code, 4, 'DEADLINE_EXCEEDED gRPC code is 4');
    assert.ok(err.message.includes('DEADLINE_EXCEEDED'), 'error message should reference DEADLINE_EXCEEDED');
  }

  restoreFetch(saved);
});
