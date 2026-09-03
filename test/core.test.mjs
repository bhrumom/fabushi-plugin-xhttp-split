import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import {
  ALL_VIEWER_EXCEPT_HOST_POLICY_ID,
  CACHE_DISABLED_POLICY_ID,
  buildClientConfig,
  buildDistributionConfig,
  buildPlan,
  buildRemoteVerificationScript,
  buildVlessLink,
  buildVpsBootstrapScript,
  validateSettings,
  validateSsh,
} from '../scripts/core.mjs';
import { TOOL_DEFINITIONS } from '../scripts/xhttp-split.mjs';

const input = {
  upstreamDomain: 'xhttp.example.com',
  originDomain: 'origin-xhttp.example.com',
  originIp: '203.0.113.10',
  path: '/test-path/',
  uuid: '54bc1c2f-26f3-44b7-89cf-1f4a6dc7b5c5',
  remark: 'My XHTTP',
  awsProfile: 'fabushi-xhttp',
  sshHost: '203.0.113.10',
  sshUser: 'ubuntu',
  sshPassword: 'must-not-leak',
};

test('settings always use public 443 and local-only Xray port', () => {
  const result = validateSettings(input);
  assert.equal(result.originPort, 443);
  assert.equal(result.localXrayPort, 8443);
  assert.equal(result.path, '/test-path/');
});

test('settings generate UUID and path when omitted', () => {
  const result = validateSettings({ upstreamDomain: 'xhttp.example.com', originDomain: 'origin.example.com' });
  assert.match(result.uuid, /^[0-9a-f-]{36}$/);
  assert.match(result.path, /^\/[0-9a-f]{24}\/$/);
});

test('SSH validation supports key, password and agent without persisting credentials', () => {
  assert.equal(validateSsh(input).user, 'ubuntu');
  const plan = buildPlan(input);
  assert.equal(plan.ssh.authentication, 'password');
  assert.equal(JSON.stringify(plan).includes('must-not-leak'), false);
  assert.equal(plan.steps.some((step) => step.app === 'bhrum2'), false);
});

test('CloudFront config matches the proven no-cache gRPC behavior', () => {
  const config = buildDistributionConfig(input, 'stable-reference');
  const origin = config.Origins.Items[0].CustomOriginConfig;
  const behavior = config.DefaultCacheBehavior;
  assert.equal(origin.HTTPSPort, 443);
  assert.equal(origin.OriginProtocolPolicy, 'https-only');
  assert.equal(behavior.CachePolicyId, CACHE_DISABLED_POLICY_ID);
  assert.equal(behavior.OriginRequestPolicyId, ALL_VIEWER_EXCEPT_HOST_POLICY_ID);
  assert.equal(behavior.GrpcConfig.Enabled, true);
  assert.equal(behavior.Compress, false);
  assert.equal(config.WebACLId, '');
});

test('client uses Cloudflare upstream and CloudFront automatic downlink mode', () => {
  const config = buildClientConfig(input, { downloadDomain: 'd111.cloudfront.net' });
  const stream = config.outbounds[0].streamSettings;
  assert.equal(config.outbounds[0].settings.vnext[0].address, 'xhttp.example.com');
  assert.equal(stream.xhttpSettings.mode, 'stream-up');
  assert.equal(stream.xhttpSettings.extra.downloadSettings.address, 'd111.cloudfront.net');
  assert.equal(stream.xhttpSettings.extra.downloadSettings.xhttpSettings.mode, 'auto');
  const link = buildVlessLink(input, { downloadDomain: 'd111.cloudfront.net' });
  assert.match(link, /^vless:\/\//);
  assert.match(decodeURIComponent(link), /d111\.cloudfront\.net/);
});

test('bootstrap script is shell-valid, binds Xray locally and never contains SSH password', () => {
  const script = buildVpsBootstrapScript(input);
  assert.match(script, /127\.0\.0\.1/);
  assert.match(script, /fabushi-xhttp-split/);
  assert.equal(script.includes('must-not-leak'), false);
  const checked = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
  assert.equal(checked.status, 0, checked.stderr);
});

test('verification script is shell-valid and performs a real SOCKS request', () => {
  const script = buildRemoteVerificationScript(input, { downloadDomain: 'd111.cloudfront.net' });
  assert.match(script, /--socks5-hostname/);
  assert.match(script, /XHTTP_VERIFIED=1/);
  const checked = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
  assert.equal(checked.status, 0, checked.stderr);
});

test('tool surface exposes SSH and one-click setup without VPS connector tools', () => {
  const names = TOOL_DEFINITIONS.map((item) => item.name);
  assert.ok(names.includes('xhttp_ssh_status'));
  assert.ok(names.includes('xhttp_setup'));
  assert.equal(names.includes('xhttp_vps_status'), false);
  assert.equal(names.includes('xhttp_vps_prepare'), false);
});
