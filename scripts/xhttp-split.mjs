#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import crypto from 'node:crypto';
import {
  APPLY_CONFIRMATION,
  buildClientConfig,
  buildDistributionConfig,
  buildPlan,
  buildRemoteVerificationScript,
  buildVlessLink,
  buildVpsBootstrapScript,
  validateSettings,
  validateSsh,
} from './core.mjs';

const stateDir = process.env.FABUSHI_XHTTP_STATE_DIR || path.join(os.homedir(), '.config', 'fabushi', 'xhttp-split');
const stateFile = path.join(stateDir, 'state.json');
let oauthServer;

function tool(name, description, properties = {}, required = [], readOnlyHint = true) {
  return { name, description, inputSchema: { type: 'object', properties, ...(required.length ? { required } : {}) }, annotations: { readOnlyHint } };
}

const cloud = {
  upstreamDomain: { type: 'string', description: 'Cloudflare 上行域名，例如 xhttp.example.com' },
  originDomain: { type: 'string', description: '仅 DNS 的 CloudFront 源站域名，例如 origin-xhttp.example.com' },
  originIp: { type: 'string', description: '可选；留空时通过 SSH 自动检测 VPS 公网 IP' },
  path: { type: 'string', description: '可选；留空时自动生成随机 XHTTP 路径' },
  uuid: { type: 'string', description: '可选；留空时自动生成 UUID' },
  remark: { type: 'string', default: 'XHTTP Split' },
  awsProfile: { type: 'string', default: 'fabushi-xhttp' },
  awsRegion: { type: 'string', default: 'us-east-1' },
};

const ssh = {
  sshHost: { type: 'string', description: 'VPS IP 或域名' },
  sshPort: { type: 'integer', minimum: 1, maximum: 65535, default: 22 },
  sshUser: { type: 'string', default: 'root' },
  sshIdentityFile: { type: 'string', description: '可选；SSH 私钥文件路径，支持 ssh-agent 和默认密钥' },
  sshPassword: { type: 'string', format: 'password', description: '可选；仅用于本次连接，不会保存' },
};

export const TOOL_DEFINITIONS = [
  tool('xhttp_status', '检查 AWS CLI 登录、Cloudflare 授权和最近一次部署结果。'),
  tool('xhttp_aws_login', '打开浏览器完成 AWS CLI 临时登录。', { profile: cloud.awsProfile, region: cloud.awsRegion }, [], false),
  tool('xhttp_cloudflare_login', '打开 Cloudflare OAuth 登录；若发行版未配置 OAuth Client，可使用 API Token。', {}, [], false),
  tool('xhttp_cloudflare_token', '保存并验证受限 Cloudflare API Token。Token 只保存在当前电脑。', { token: { type: 'string', format: 'password' } }, ['token'], false),
  tool('xhttp_ssh_status', '通过 SSH 只读检查 VPS、sudo、系统、磁盘、公网 IP 和 443 端口。', ssh, ['sshHost']),
  tool('xhttp_plan', '生成完整的一键部署预览，不执行写操作。', { ...cloud, ...ssh }, ['upstreamDomain', 'originDomain', 'sshHost']),
  tool('xhttp_setup', '一键完成 DNS、VPS、TLS、Xray、HAProxy、CloudFront、客户端配置和真实连通性验证。', { ...cloud, ...ssh, confirmation: { type: 'string', description: `确认语：${APPLY_CONFIRMATION}` } }, ['upstreamDomain', 'originDomain', 'sshHost', 'confirmation'], false),
  tool('xhttp_apply', '兼容旧版的一键搭建入口，行为与 xhttp_setup 相同。', { ...cloud, ...ssh, confirmation: { type: 'string' } }, ['upstreamDomain', 'originDomain', 'sshHost', 'confirmation'], false),
  tool('xhttp_client_config', '根据已创建的 CloudFront 域名重新生成客户端 JSON 和导入链接。', { ...cloud, downloadDomain: { type: 'string' } }, ['upstreamDomain', 'originDomain', 'uuid', 'path', 'downloadDomain']),
];

function readState() {
  try { return JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { return {}; }
}

function writeState(update) {
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const next = { ...readState(), ...update };
  fs.writeFileSync(stateFile, JSON.stringify(next, null, 2), { mode: 0o600 });
  fs.chmodSync(stateFile, 0o600);
  return next;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8', timeout: options.timeout ?? 30_000, maxBuffer: 16 * 1024 * 1024,
    env: options.env || process.env, input: options.input,
  });
  return { ok: !result.error && result.status === 0, status: result.status, stdout: String(result.stdout || '').trim(), stderr: String(result.stderr || result.error || '').trim() };
}

function openUrl(url) {
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawn(command, args, { detached: true, stdio: 'ignore' });
  child.unref();
}

function sshOptions(input = {}) {
  const value = validateSsh(input);
  const args = [
    '-p', String(value.port),
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'NumberOfPasswordPrompts=1',
  ];
  if (value.identityFile) {
    const identityFile = value.identityFile.startsWith('~/') ? path.join(os.homedir(), value.identityFile.slice(2)) : path.resolve(value.identityFile);
    if (!fs.existsSync(identityFile)) throw new Error(`SSH 私钥不存在：${identityFile}`);
    args.push('-i', identityFile, '-o', 'IdentitiesOnly=yes');
  }
  args.push(`${value.user}@${value.host}`, 'bash -s');
  return { value, args };
}

function sshRun(input, script, timeout = 120_000) {
  const { value, args } = sshOptions(input);
  let temporary;
  let env = process.env;
  try {
    if (value.password) {
      temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'fabushi-ssh-'));
      const askpass = path.join(temporary, 'askpass.sh');
      fs.writeFileSync(askpass, '#!/bin/sh\nprintf %s "$FABUSHI_SSH_PASSWORD"\n', { mode: 0o700 });
      env = { ...process.env, SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: process.env.DISPLAY || ':0', FABUSHI_SSH_PASSWORD: value.password };
    }
    const result = run('ssh', args, { input: script, timeout, env });
    if (!result.ok) throw new Error(result.stderr || result.stdout || `SSH 执行失败（状态 ${result.status}）`);
    return result.stdout;
  } finally {
    if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function parseKeyValues(text) {
  const result = {};
  for (const line of String(text).split(/\r?\n/)) {
    const index = line.indexOf('=');
    if (index > 0) result[line.slice(0, index)] = line.slice(index + 1);
  }
  return result;
}

async function sshStatus(args) {
  const script = `set -e\nif [ "$(id -u)" -ne 0 ]; then sudo -n true; fi\necho OS_ID=$(awk -F= '$1=="ID"{gsub(/\"/,"",$2);print $2}' /etc/os-release)\necho OS_VERSION=$(awk -F= '$1=="VERSION_ID"{gsub(/\"/,"",$2);print $2}' /etc/os-release)\necho ARCH=$(uname -m)\necho DISK_FREE_KB=$(df -Pk / | awk 'NR==2{print $4}')\necho PUBLIC_IP=$(curl -4fsS --max-time 15 https://api.ipify.org)\necho PORT443=$(ss -lntp 2>/dev/null | awk '$4 ~ /:443$/ {print $NF}' | head -1 || true)\necho SUDO_OK=1\n`;
  const values = parseKeyValues(sshRun(args, script, 45_000));
  if (!['ubuntu', 'debian'].includes(values.OS_ID)) throw new Error(`暂只支持 Ubuntu/Debian，当前为 ${values.OS_ID || '未知系统'}`);
  if (Number(values.DISK_FREE_KB || 0) < 2 * 1024 * 1024) throw new Error('VPS 根分区可用空间不足 2 GB');
  return {
    ok: true,
    os: `${values.OS_ID} ${values.OS_VERSION}`,
    arch: values.ARCH,
    publicIp: values.PUBLIC_IP,
    diskFreeBytes: Number(values.DISK_FREE_KB || 0) * 1024,
    port443: values.PORT443 || '空闲',
    sudo: values.SUDO_OK === '1',
  };
}

async function cfFetch(endpoint, options = {}) {
  const token = readState().cloudflare?.accessToken;
  if (!token) throw new Error('Cloudflare 尚未授权');
  const response = await fetch(`https://api.cloudflare.com/client/v4${endpoint}`, {
    ...options,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...options.headers },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.success === false) throw new Error(body.errors?.map((item) => item.message).join('; ') || `Cloudflare HTTP ${response.status}`);
  return body.result;
}

async function status() {
  const version = run('aws', ['--version']);
  const profile = readState().awsProfile || 'fabushi-xhttp';
  const identity = version.ok ? run('aws', ['sts', 'get-caller-identity', '--profile', profile, '--output', 'json'], { timeout: 20_000 }) : { ok: false };
  let cloudflare = { authenticated: false };
  if (readState().cloudflare?.accessToken) {
    try { cloudflare = { authenticated: true, token: await cfFetch('/user/tokens/verify') }; } catch (error) { cloudflare = { authenticated: false, error: error.message }; }
  }
  return {
    aws: { installed: version.ok, version: version.stdout || version.stderr, profile, authenticated: identity.ok, identity: identity.ok ? JSON.parse(identity.stdout) : undefined },
    cloudflare,
    ssh: { mode: 'direct', credentialsStored: false },
    lastDeployment: readState().lastDeployment,
  };
}

async function awsLogin(args) {
  const version = run('aws', ['--version']);
  if (!version.ok) return { ok: false, code: 'aws_cli_missing', message: '需要 AWS CLI 2.32.0 或更高版本。', installUrl: 'https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html' };
  const profile = String(args.profile || 'fabushi-xhttp');
  const region = String(args.region || 'us-east-1');
  const result = run('aws', ['login', '--profile', profile, '--region', region, '--no-cli-pager'], { timeout: 12 * 60_000 });
  if (!result.ok) throw new Error(result.stderr || result.stdout || 'AWS 登录失败');
  writeState({ awsProfile: profile });
  return { ok: true, profile, region, message: 'AWS 临时登录成功。' };
}

function base64url(value) { return Buffer.from(value).toString('base64url'); }

async function cloudflareLogin() {
  const clientId = process.env.CLOUDFLARE_OAUTH_CLIENT_ID;
  if (!clientId) return { ok: false, code: 'oauth_client_missing', message: '此发行版尚未配置 Cloudflare OAuth Client，请点击“Token 登录”。', tokenUrl: 'https://dash.cloudflare.com/profile/api-tokens' };
  if (oauthServer) throw new Error('已有 Cloudflare 授权正在等待完成');
  const port = Number(process.env.CLOUDFLARE_OAUTH_CALLBACK_PORT || 43119);
  const redirectUri = `http://127.0.0.1:${port}/callback`;
  const oauthState = crypto.randomBytes(24).toString('hex');
  const verifier = base64url(crypto.randomBytes(48));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  oauthServer = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, redirectUri);
      if (url.pathname !== '/callback' || url.searchParams.get('state') !== oauthState) throw new Error('授权回调无效');
      const code = url.searchParams.get('code');
      if (!code) throw new Error(url.searchParams.get('error_description') || 'Cloudflare 没有返回授权码');
      const tokenResponse = await fetch('https://dash.cloudflare.com/oauth2/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: redirectUri, code_verifier: verifier }),
      });
      const token = await tokenResponse.json();
      if (!tokenResponse.ok || !token.access_token) throw new Error(token.error_description || token.error || 'Token 交换失败');
      writeState({ cloudflare: { accessToken: token.access_token, refreshToken: token.refresh_token, expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : null } });
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end('<h1>Cloudflare 授权成功</h1><p>可以关闭此页面并返回小程序。</p>');
    } catch (error) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
      response.end(`授权失败：${error.message}`);
    } finally { oauthServer?.close(); oauthServer = undefined; }
  });
  await new Promise((resolve, reject) => oauthServer.listen(port, '127.0.0.1', resolve).once('error', reject));
  const authorize = new URL('https://dash.cloudflare.com/oauth2/auth');
  authorize.search = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, state: oauthState, code_challenge: challenge, code_challenge_method: 'S256', scope: process.env.CLOUDFLARE_OAUTH_SCOPES || 'zone.read dns.write ssl.write origin-rules.write' });
  openUrl(authorize.toString());
  return { ok: true, pending: true, message: 'Cloudflare 授权页已打开。完成后刷新状态。' };
}

async function saveCloudflareToken(args) {
  const token = String(args.token || '').trim();
  if (!token) throw new Error('Token 不能为空');
  writeState({ cloudflare: { accessToken: token, source: 'api-token' } });
  try { await cfFetch('/user/tokens/verify'); } catch (error) { writeState({ cloudflare: null }); throw error; }
  return { ok: true, message: 'Cloudflare Token 已验证并只保存在当前电脑。' };
}

async function findZone(settings) {
  const candidates = [settings.upstreamDomain, settings.originDomain];
  for (const candidate of candidates) {
    const parts = candidate.split('.');
    for (let index = 0; index < parts.length - 1; index += 1) {
      const name = parts.slice(index).join('.');
      const zones = await cfFetch(`/zones?name=${encodeURIComponent(name)}&status=active`);
      if (zones?.length) return zones[0];
    }
  }
  throw new Error('Cloudflare 中找不到域名所属的活动 Zone');
}

async function upsertARecord(zoneId, name, content, proxied) {
  const existing = await cfFetch(`/zones/${zoneId}/dns_records?type=A&name=${encodeURIComponent(name)}`);
  const payload = { type: 'A', name, content, ttl: 1, proxied };
  if (existing?.[0]) return cfFetch(`/zones/${zoneId}/dns_records/${existing[0].id}`, { method: 'PUT', body: JSON.stringify(payload) });
  return cfFetch(`/zones/${zoneId}/dns_records`, { method: 'POST', body: JSON.stringify(payload) });
}

async function prepareCloudflareDns(settings) {
  const zone = await findZone(settings);
  await upsertARecord(zone.id, settings.upstreamDomain, settings.originIp, false);
  await upsertARecord(zone.id, settings.originDomain, settings.originIp, false);
  return zone;
}

async function finalizeCloudflare(settings, zone) {
  await upsertARecord(zone.id, settings.upstreamDomain, settings.originIp, true);
  await upsertARecord(zone.id, settings.originDomain, settings.originIp, false);
  await cfFetch(`/zones/${zone.id}/settings/ssl`, { method: 'PATCH', body: JSON.stringify({ value: 'full' }) });
  await cfFetch(`/zones/${zone.id}/settings/grpc`, { method: 'PATCH', body: JSON.stringify({ value: 'on' }) });
  try {
    const ruleset = await cfFetch(`/zones/${zone.id}/rulesets/phases/http_request_origin/entrypoint`);
    const descriptions = new Set([`Fabushi XHTTP ${settings.upstreamDomain}`, `XHTTP 回源到 8443`]);
    const rules = (ruleset.rules || []).filter((item) => !descriptions.has(item.description));
    if (rules.length !== (ruleset.rules || []).length) {
      await cfFetch(`/zones/${zone.id}/rulesets/${ruleset.id}`, { method: 'PUT', body: JSON.stringify({ name: ruleset.name, description: ruleset.description || '', kind: ruleset.kind, phase: ruleset.phase, rules }) });
    }
  } catch {
    // 没有 Origin Rules 时无需创建；443 是标准回源端口。
  }
  return { zoneId: zone.id, zoneName: zone.name, upstreamDomain: settings.upstreamDomain, originDomain: settings.originDomain };
}

function awsJson(args, timeout = 60_000) {
  const result = run('aws', [...args, '--output', 'json', '--no-cli-pager'], { timeout });
  if (!result.ok) throw new Error(result.stderr || result.stdout || `AWS 命令失败：${args.join(' ')}`);
  return JSON.parse(result.stdout);
}

function existingDistribution(profile, marker) {
  const data = awsJson(['cloudfront', 'list-distributions', '--profile', profile]);
  return (data.DistributionList?.Items || []).find((item) => item.Comment === marker);
}

function writeTemporaryJson(value, callback) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'fabushi-xhttp-'));
  const file = path.join(temporary, 'config.json');
  try {
    fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
    return callback(file);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

function createOrUpdateDistribution(settings) {
  const marker = `fabushi-xhttp-split:download:${settings.originDomain}:443`;
  const existing = existingDistribution(settings.awsProfile, marker);
  if (!existing) {
    const config = buildDistributionConfig(settings);
    return writeTemporaryJson(config, (file) => {
      const data = awsJson(['cloudfront', 'create-distribution', '--profile', settings.awsProfile, '--distribution-config', `file://${file}`], 180_000);
      return { id: data.Distribution.Id, domainName: data.Distribution.DomainName, status: data.Distribution.Status, reused: false };
    });
  }
  const current = awsJson(['cloudfront', 'get-distribution-config', '--profile', settings.awsProfile, '--id', existing.Id]);
  const config = buildDistributionConfig(settings, current.DistributionConfig.CallerReference);
  return writeTemporaryJson(config, (file) => {
    const data = awsJson(['cloudfront', 'update-distribution', '--profile', settings.awsProfile, '--id', existing.Id, '--if-match', current.ETag, '--distribution-config', `file://${file}`], 180_000);
    return { id: data.Distribution.Id, domainName: data.Distribution.DomainName, status: data.Distribution.Status, reused: true };
  });
}

function waitDistribution(profile, id) {
  const result = run('aws', ['cloudfront', 'wait', 'distribution-deployed', '--profile', profile, '--id', id, '--no-cli-pager'], { timeout: 15 * 60_000 });
  if (!result.ok) throw new Error(result.stderr || '等待 CloudFront 部署完成超时');
}

async function setup(args) {
  if (args.confirmation !== APPLY_CONFIRMATION) throw new Error(`需要输入确认语：${APPLY_CONFIRMATION}`);
  const initial = validateSettings(args);
  validateSsh(args);
  const identity = run('aws', ['sts', 'get-caller-identity', '--profile', initial.awsProfile, '--output', 'json', '--no-cli-pager']);
  if (!identity.ok) throw new Error('AWS 尚未登录，或当前身份没有 CloudFront 权限');
  await cfFetch('/user/tokens/verify');

  const vps = await sshStatus(args);
  const settings = validateSettings({ ...initial, originIp: initial.originIp || vps.publicIp });
  const zone = await prepareCloudflareDns(settings);
  const bootstrapOutput = sshRun(args, buildVpsBootstrapScript(settings), 15 * 60_000);
  if (!bootstrapOutput.includes('XHTTP_READY=1')) throw new Error('VPS 配置完成但没有返回就绪标记');
  const cloudflare = await finalizeCloudflare(settings, zone);
  const download = createOrUpdateDistribution(settings);
  waitDistribution(settings.awsProfile, download.id);

  const clientConfig = buildClientConfig(settings, { downloadDomain: download.domainName });
  const importLink = buildVlessLink(settings, { downloadDomain: download.domainName });
  const verificationOutput = sshRun(args, buildRemoteVerificationScript(settings, { downloadDomain: download.domainName }), 90_000);
  if (!verificationOutput.includes('XHTTP_VERIFIED=1')) throw new Error('线路已创建，但真实代理验证没有通过');

  const completedAt = new Date().toISOString();
  const lastDeployment = {
    completedAt,
    upstreamDomain: settings.upstreamDomain,
    originDomain: settings.originDomain,
    publicIp: settings.originIp,
    cloudFrontDomain: download.domainName,
    distributionId: download.id,
    verified: true,
  };
  writeState({ awsProfile: settings.awsProfile, lastDeployment });
  return {
    ok: true,
    verified: true,
    completedAt,
    settings,
    vps,
    cloudflare,
    download: { ...download, status: 'Deployed' },
    importLink,
    clientConfig,
    verification: verificationOutput.split(/\r?\n/).filter((line) => /^(ip|colo|tls|http|XHTTP_VERIFIED)=/.test(line)),
    security: { sshPasswordStored: false, clientCredentialSensitive: true, wafEnabled: false },
  };
}

export async function callTool(name, args = {}) {
  if (name === 'xhttp_status') return status();
  if (name === 'xhttp_aws_login') return awsLogin(args);
  if (name === 'xhttp_cloudflare_login') return cloudflareLogin();
  if (name === 'xhttp_cloudflare_token') return saveCloudflareToken(args);
  if (name === 'xhttp_ssh_status') return sshStatus(args);
  if (name === 'xhttp_plan') return buildPlan(args, await sshStatus(args));
  if (name === 'xhttp_setup' || name === 'xhttp_apply') return setup(args);
  if (name === 'xhttp_client_config') return {
    clientConfig: buildClientConfig(args, { downloadDomain: args.downloadDomain }),
    importLink: buildVlessLink(args, { downloadDomain: args.downloadDomain }),
  };
  throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32601 });
}

async function mcpServe() {
  process.stdin.setEncoding('utf8');
  let buffer = '';
  for await (const chunk of process.stdin) {
    buffer += chunk;
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      let request;
      try {
        request = JSON.parse(line);
        let result;
        if (request.method === 'initialize') result = { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'xhttp-split', version: '0.2.0' } };
        else if (request.method === 'notifications/initialized') continue;
        else if (request.method === 'tools/list') result = { tools: TOOL_DEFINITIONS };
        else if (request.method === 'tools/call') {
          const output = await callTool(request.params?.name, request.params?.arguments || {});
          result = { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }], structuredContent: output };
        } else throw Object.assign(new Error(`Unsupported method: ${request.method}`), { code: -32601 });
        process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: request.id, result })}\n`);
      } catch (error) {
        process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: request?.id ?? null, error: { code: Number(error.code) || -32000, message: error.message } })}\n`);
      }
    }
  }
}

export async function main(argv = process.argv.slice(2)) {
  if ((argv[0] || 'mcp-serve') === 'mcp-serve') return mcpServe();
  const name = argv[0];
  const args = argv[1] ? JSON.parse(argv[1]) : {};
  process.stdout.write(`${JSON.stringify(await callTool(name, args), null, 2)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
