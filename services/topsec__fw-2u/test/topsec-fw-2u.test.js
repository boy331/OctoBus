import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';

import {
  METHOD_ACTIVATE_FULL,
  METHOD_ACTIVATE_PATH,
  METHOD_ADD_FULL,
  METHOD_ADD_PATH,
  METHOD_DELETE_FULL,
  METHOD_DELETE_PATH,
  METHOD_LOGIN_FULL,
  METHOD_LOGIN_PATH,
  METHOD_LOGOUT_FULL,
  METHOD_LOGOUT_PATH,
  _test,
  handlers,
  rpcdef,
} from '../src/topsec-fw-2u.js';
import { service } from '../src/service.js';
import { createMockServer, encodePayload } from './mock_upstream.js';

const originalFetch = globalThis.fetch;

const buildCtx = (overrides = {}) => ({
  serviceId: 'topsec__fw-2u',
  instanceId: 'inst-100',
  config: {
    host: 'https://fw.example.com:4443',
    timeoutMs: 3000,
    ...(overrides.config || {}),
  },
  secret: {
    username: 'api_user',
    password: 'TopSecret!',
    ...(overrides.secret || {}),
  },
  metadata: { request_id: 'req-100', ...(overrides.metadata || {}) },
  limits: { timeoutMs: 3000, ...(overrides.limits || {}) },
});

const callHandler = (method, request = {}, ctx = buildCtx()) => handlers[method]({ ...ctx, request });

const responseOf = (status, body, headers = {}) => ({
  status,
  headers: {
    get(name) {
      return headers[String(name).toLowerCase()] || null;
    },
    getSetCookie() {
      return Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [];
    },
  },
  arrayBuffer: async () => new TextEncoder().encode(String(body)).buffer,
});

const setFetch = (impl) => {
  globalThis.fetch = impl;
};

const expectGrpcError = async (fn, legacyCode, checker = () => {}) => {
  let caught;
  try {
    await fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(caught, 'expected function to reject');
  assert.ok(caught instanceof GrpcError);
  assert.equal(caught.legacyCode, legacyCode);
  assert.equal(caught.code, ({
    INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
    UNAUTHENTICATED: grpcStatus.UNAUTHENTICATED,
    UNAVAILABLE: grpcStatus.UNAVAILABLE,
    UNKNOWN: grpcStatus.UNKNOWN,
  })[legacyCode]);
  assert.match(caught.message, new RegExp(`^${legacyCode}:`));
  checker(caught);
};

test.afterEach(() => {
  globalThis.fetch = originalFetch;
  _test.sessionCache.clear();
});

test('service exports single-argument SDK handlers and rpcdef path handlers', () => {
  assert.equal(typeof service, 'object');
  for (const method of [METHOD_LOGIN_FULL, METHOD_ACTIVATE_FULL, METHOD_ADD_FULL, METHOD_DELETE_FULL, METHOD_LOGOUT_FULL]) {
    assert.equal(typeof handlers[method], 'function');
    assert.equal(handlers[method].length, 0);
  }
  const defs = rpcdef(buildCtx());
  for (const path of [METHOD_LOGIN_PATH, METHOD_ACTIVATE_PATH, METHOD_ADD_PATH, METHOD_DELETE_PATH, METHOD_LOGOUT_PATH]) {
    assert.equal(typeof defs[path], 'function');
  }
});

test('Login uses ctx.secret credentials, ignores request credentials, and sanitizes response', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url: String(url), init, form: Object.fromEntries(new URLSearchParams(init.body).entries()) };
    return responseOf(
      200,
      encodePayload({ result: true, data: { authid: 'u-1' }, tokens: ['fallback-token'], secret: 'sec-1' }, '1234567890abcdef'),
      { 'set-cookie': ['PHPSESSID=sid-1; Path=/', 'changeVsid=0; Path=/'] },
    );
  });

  const res = await callHandler(METHOD_LOGIN_FULL, { username: 'request-user', password: 'request-pass' });
  const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from('ngfwrestapilogin'), Buffer.from('ngfwrestapilogin'));
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(Buffer.from(captured.form.password, 'base64')), decipher.final()]).toString('utf8').replace(/\u0000+$/g, '');

  assert.equal(captured.url, 'https://fw.example.com:4443/home/login/addNoCode/');
  assert.equal(captured.form.name, 'api_user');
  assert.equal(decrypted, 'TopSecret!');
  assert.deepEqual(res, { status_code: 200, success: true, message: 'success' });
  assert.equal(Object.hasOwn(res, 'raw_body'), false);
  assert.equal(Object.hasOwn(res, 'session'), false);
});

test('AddBlacklistIP logs in internally, ignores request session, and returns no token or raw body', async () => {
  const seen = [];
  setFetch(async (url, init) => {
    seen.push({ url: String(url), init, form: Object.fromEntries(new URLSearchParams(init.body || '').entries()) });
    if (String(url).endsWith('/home/login/addNoCode/')) {
      return responseOf(200, encodePayload({ result: true, data: { authid: 'mark-1' }, secret: 'sec-1' }, 'tok-login-1234567'), {
        'set-cookie': ['PHPSESSID=sid-1; Path=/'],
      });
    }
    return responseOf(200, encodePayload({ result: true, data: 'success' }, 'tok-rotated-1234'));
  });

  const res = await callHandler(METHOD_ADD_FULL, {
    session: { token: 'request-token', user_mark: 'request-mark', cookie: 'request-cookie' },
    ips: ['198.51.100.10'],
  });

  assert.equal(seen.length, 2);
  assert.equal(seen[1].url, 'https://fw.example.com:4443/home/default/blackListSpread/addTuple/?userMark=mark-1');
  assert.equal(seen[1].form.token, 'tok-login-1234567');
  assert.equal(seen[1].form['commands[0][pf_blacklist_add_tuple][0][tuple]'], '198.51.100.10,,,,,;');
  assert.deepEqual(res, { status_code: 200, success: true, message: 'success' });
  assert.equal(JSON.stringify(res).includes('tok-'), false);
  assert.equal(JSON.stringify(res).includes('PHPSESSID'), false);
});

test('mock upstream supports internal login cache across add delete logout', async () => {
  const mock = createMockServer();
  const host = await mock.start();
  const ctx = buildCtx({ config: { host }, secret: { username: 'demo', password: 'secret' } });
  try {
    const add = await callHandler(METHOD_ADD_FULL, { ips: ['198.51.100.20'] }, ctx);
    assert.equal(add.success, true);
    const del = await callHandler(METHOD_DELETE_FULL, { ips: ['198.51.100.20'] }, ctx);
    assert.equal(del.success, true);
    const logout = await callHandler(METHOD_LOGOUT_FULL, {}, ctx);
    assert.equal(logout.success, true);
    assert.equal(mock.requests.length, 4);
    assert.deepEqual(mock.requests.map((item) => item.path), [
      '/home/login/addNoCode/',
      '/home/default/blackListSpread/addTuple/',
      '/home/default/blackListSpread/deleteLots/',
      '/home/index/logout/',
    ]);
  } finally {
    await mock.close();
  }
});

test('validation and upstream failures do not leak raw response material', async () => {
  await expectGrpcError(() => callHandler(METHOD_ADD_FULL, { ips: [] }), 'INVALID_ARGUMENT', (err) => {
    assert.match(err.message, /ips is required/);
  });
  await expectGrpcError(() => callHandler(METHOD_LOGIN_FULL, {}, buildCtx({ secret: { password: '' } })), 'UNAUTHENTICATED');

  setFetch(async () => {
    throw Object.assign(new Error('boom'), { cause: new Error('timeout') });
  });
  await expectGrpcError(() => callHandler(METHOD_LOGIN_FULL), 'UNAVAILABLE', (err) => {
    assert.match(err.message, /timeout/);
    assert.equal(err.message.includes('TopSecret!'), false);
  });
});

test('helper functions cover payload, cookie, cache, and scalar branches', () => {
  assert.equal(_test.readString({ value: { value: 'deep' } }), 'deep');
  assert.equal(_test.firstDefined(undefined, null, 'x'), 'x');
  assert.equal(_test.isIPv4('192.0.2.1'), true);
  assert.equal(_test.isIPv6('2001:db8::1'), true);
  assert.deepEqual(_test.readIpList({ ipList: { values: ['198.51.100.30'] } }), ['198.51.100.30']);
  assert.equal(_test.normalizeCookie('a=1; a=2; think_language=en'), 'a=1; think_language=en');
  assert.equal(_test.gatherCookies({ raw: () => ({ 'set-cookie': ['a=1; Path=/', 'b=2; Path=/'] }) }), 'a=1; b=2');
  assert.equal(_test.decodeTopSecPayload(Buffer.from(JSON.stringify({ ok: true })).toString('base64')).parsed.ok, true);
  assert.equal(_test.buildUrl('https://h', '/p/', { a: '1', b: '', c: null }), 'https://h/p/?a=1');
  assert.deepEqual(_test.buildBaseResponse(204, ''), { status_code: 204, success: true, message: 'success' });
  assert.equal(_test.cacheIdentity(buildCtx(), 'https://fw', 'u'), JSON.stringify(['topsec__fw-2u', 'inst-100', 'https://fw', 'u']));
});
