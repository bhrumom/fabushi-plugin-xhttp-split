import crypto from 'node:crypto';

export const CACHE_DISABLED_POLICY_ID = '4135ea2d-6df8-44a3-9df3-4b5a84be39ad';
export const ALL_VIEWER_EXCEPT_HOST_POLICY_ID = 'b689b0a8-53d0-40ab-baf2-68738e2966ac';
export const APPLY_CONFIRMATION = '创建 XHTTP 线路';

function requiredString(value, name) {
  const result = String(value ?? '').trim();
  if (!result) throw new Error(`${name} 不能为空`);
  return result;
}

function hostname(value, name) {
  const result = requiredString(value, name).replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+$/i.test(result) || !result.includes('.')) throw new Error(`${name} 不是有效域名`);
  return result.toLowerCase();
}

export function normalizePath(value) {
  let result = requiredString(value, 'XHTTP path');
  if (!result.startsWith('/')) result = `/${result}`;
  if (!result.endsWith('/')) result += '/';
  if (!/^\/[A-Za-z0-9._~/-]+\/$/.test(result)) throw new Error('XHTTP path 含有不支持的字符');
  return result;
}

export function validateSsh(input = {}) {
  const port = Number(input.sshPort || 22);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('SSH 端口必须是 1-65535');
  const host = requiredString(input.sshHost, 'SSH 主机');
  if (!/^[a-z0-9.:[\]-]+$/i.test(host)) throw new Error('SSH 主机格式不正确');
  const user = String(input.sshUser || 'root').trim();
  if (!/^[a-z_][a-z0-9_-]*[$]?$/i.test(user)) throw new Error('SSH 用户名格式不正确');
  const identityFile = String(input.sshIdentityFile || '').trim();
  const password = String(input.sshPassword || '');
  return { host, port, user, identityFile, password };
}

export function validateSettings(input = {}) {
  const uuid = String(input.uuid || crypto.randomUUID()).trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid)) throw new Error('UUID 格式不正确');
  const generatedPath = `/${crypto.randomBytes(12).toString('hex')}/`;
  const result = {
    strategy: 'cloudflare-cloudfront',
    upstreamDomain: hostname(input.upstreamDomain, 'Cloudflare 上行域名'),
    originDomain: hostname(input.originDomain, 'CloudFront 源站域名'),
    originIp: String(input.originIp || '').trim(),
    originPort: 443,
    localXrayPort: 8443,
    path: normalizePath(input.path || generatedPath),
    uuid,
    remark: String(input.remark ?? 'XHTTP Split').trim() || 'XHTTP Split',
    awsProfile: String(input.awsProfile ?? 'fabushi-xhttp').trim() || 'fabushi-xhttp',
    awsRegion: String(input.awsRegion ?? 'us-east-1').trim() || 'us-east-1',
  };
  if (result.originIp && !/^\d{1,3}(\.\d{1,3}){3}$/.test(result.originIp) && !result.originIp.includes(':')) throw new Error('VPS 公网 IP 格式不正确');
  return result;
}

export function buildDistributionConfig(settings, callerReference) {
  const value = validateSettings(settings);
  const reference = callerReference || `fabushi-xhttp-download-${Date.now()}-${crypto.randomUUID()}`;
  const originId = 'xhttp-download-origin';
  return {
    CallerReference: reference,
    Aliases: { Quantity: 0 },
    DefaultRootObject: '',
    Origins: {
      Quantity: 1,
      Items: [{
        Id: originId,
        DomainName: value.originDomain,
        OriginPath: '',
        CustomHeaders: { Quantity: 0 },
        CustomOriginConfig: {
          HTTPPort: 80,
          HTTPSPort: 443,
          OriginProtocolPolicy: 'https-only',
          OriginSslProtocols: { Quantity: 1, Items: ['TLSv1.2'] },
          OriginReadTimeout: 60,
          OriginKeepaliveTimeout: 60,
        },
        ConnectionAttempts: 3,
        ConnectionTimeout: 10,
        OriginShield: { Enabled: false },
      }],
    },
    OriginGroups: { Quantity: 0 },
    DefaultCacheBehavior: {
      TargetOriginId: originId,
      TrustedSigners: { Enabled: false, Quantity: 0 },
      TrustedKeyGroups: { Enabled: false, Quantity: 0 },
      ViewerProtocolPolicy: 'redirect-to-https',
      AllowedMethods: {
        Quantity: 7,
        Items: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
        CachedMethods: { Quantity: 2, Items: ['GET', 'HEAD'] },
      },
      SmoothStreaming: false,
      Compress: false,
      LambdaFunctionAssociations: { Quantity: 0 },
      FunctionAssociations: { Quantity: 0 },
      FieldLevelEncryptionId: '',
      CachePolicyId: CACHE_DISABLED_POLICY_ID,
      OriginRequestPolicyId: ALL_VIEWER_EXCEPT_HOST_POLICY_ID,
      GrpcConfig: { Enabled: true },
    },
    CacheBehaviors: { Quantity: 0 },
    CustomErrorResponses: { Quantity: 0 },
    Comment: `fabushi-xhttp-split:download:${value.originDomain}:443`,
    Logging: { Enabled: false, IncludeCookies: false, Bucket: '', Prefix: '' },
    PriceClass: 'PriceClass_All',
    Enabled: true,
    ViewerCertificate: { CloudFrontDefaultCertificate: true, MinimumProtocolVersion: 'TLSv1', CertificateSource: 'cloudfront' },
    Restrictions: { GeoRestriction: { RestrictionType: 'none', Quantity: 0 } },
    WebACLId: '',
    HttpVersion: 'http2and3',
    IsIPV6Enabled: true,
  };
}

export function buildPlan(input = {}, sshInfo = {}) {
  const settings = validateSettings(input);
  const ssh = validateSsh(input);
  return {
    schemaVersion: 2,
    settings: { ...settings, uuid: '***已隐藏***' },
    ssh: { host: ssh.host, port: ssh.port, user: ssh.user, authentication: ssh.password ? 'password' : ssh.identityFile ? 'identity-file' : 'ssh-agent/default-key', ...sshInfo },
    steps: [
      { id: 'login', action: '确认 AWS 临时登录和 Cloudflare 授权', writes: false },
      { id: 'ssh', action: '通过 SSH 检查 VPS、sudo、端口与磁盘', writes: false },
      { id: 'dns-prepare', action: `创建 ${settings.upstreamDomain} 与 ${settings.originDomain} 的 DNS-only 记录`, writes: true },
      { id: 'vps', action: '安装 Xray、TLS、HAProxy；443 按 SNI 分流，Xray 仅监听本机 8443', writes: true },
      { id: 'cloudflare', action: `将 ${settings.upstreamDomain} 开启代理、Full TLS 与 gRPC`, writes: true },
      { id: 'cloudfront', action: '创建 CloudFront 下行（HTTPS 443 回源、gRPC、禁用缓存和压缩、WAF 关闭）', writes: true },
      { id: 'verify', action: '在 VPS 启动临时客户端，真实访问公网并清理测试进程', writes: false },
      { id: 'client', action: '输出一键导入链接与完整 Xray JSON', writes: false },
    ],
    warnings: [
      'CloudFront 按量计费；本程序不会启用 AWS WAF。',
      'SSH 密码不会写入状态文件；推荐使用密钥或 ssh-agent。',
      'VPS 需为 Ubuntu/Debian，并使用 root 或具备免密 sudo 的用户。',
      '如果 443 已由 Apache/Nginx 使用，会先备份配置并迁移到本机 9443，再由 HAProxy 保持原服务可用。',
    ],
    confirmation: APPLY_CONFIRMATION,
  };
}

export function buildClientOutbound(input = {}, endpoints = {}) {
  const settings = validateSettings(input);
  const downloadAddress = hostname(endpoints.downloadDomain, 'CloudFront 下行域名');
  return {
    tag: 'proxy',
    protocol: 'vless',
    settings: { vnext: [{ address: settings.upstreamDomain, port: 443, users: [{ id: settings.uuid, encryption: 'none' }] }] },
    streamSettings: {
      network: 'xhttp',
      security: 'tls',
      xhttpSettings: {
        host: settings.upstreamDomain,
        path: settings.path,
        mode: 'stream-up',
        extra: {
          xPaddingBytes: '100-1000',
          downloadSettings: {
            address: downloadAddress,
            port: 443,
            network: 'xhttp',
            security: 'tls',
            xhttpSettings: { host: downloadAddress, path: settings.path, mode: 'auto', extra: { xPaddingBytes: '100-1000' } },
            tlsSettings: { serverName: downloadAddress, alpn: ['h2', 'h3'] },
          },
        },
      },
      tlsSettings: { serverName: settings.upstreamDomain, fingerprint: 'chrome', alpn: ['h2'] },
    },
  };
}

export function buildClientConfig(input = {}, endpoints = {}) {
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'socks-in', listen: '127.0.0.1', port: 10808, protocol: 'socks', settings: { auth: 'noauth', udp: true } }],
    outbounds: [buildClientOutbound(input, endpoints), { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
  };
}

export function buildVlessLink(input = {}, endpoints = {}) {
  const settings = validateSettings(input);
  const downloadAddress = hostname(endpoints.downloadDomain, 'CloudFront 下行域名');
  const extra = {
    xPaddingBytes: '100-1000',
    downloadSettings: {
      address: downloadAddress,
      port: 443,
      network: 'xhttp',
      security: 'tls',
      xhttpSettings: { host: downloadAddress, path: settings.path, mode: 'auto', xPaddingBytes: '100-1000' },
      tlsSettings: { serverName: downloadAddress, alpn: ['h2', 'h3'] },
    },
  };
  const query = new URLSearchParams({
    encryption: 'none', security: 'tls', fp: 'chrome', alpn: 'h2,http/1.1', sni: settings.upstreamDomain,
    allowInsecure: '0', type: 'xhttp', host: settings.upstreamDomain, path: settings.path, mode: 'stream-up', extra: JSON.stringify(extra),
  });
  return `vless://${settings.uuid}@${settings.upstreamDomain}:443?${query.toString()}#${encodeURIComponent(settings.remark)}`;
}

function encode(value) { return Buffer.from(value).toString('base64'); }

export function buildVpsBootstrapScript(input = {}) {
  const settings = validateSettings(input);
  const xrayConfig = JSON.stringify({
    log: { loglevel: 'warning' },
    inbounds: [{
      tag: 'xhttp-in', listen: '127.0.0.1', port: settings.localXrayPort, protocol: 'vless',
      settings: { clients: [{ id: settings.uuid, email: 'xhttp-split' }], decryption: 'none' },
      streamSettings: {
        network: 'xhttp', security: 'tls',
        tlsSettings: { alpn: ['h2', 'http/1.1'], certificates: [{ certificateFile: `/etc/letsencrypt/live/${settings.originDomain}/fullchain.pem`, keyFile: `/etc/letsencrypt/live/${settings.originDomain}/privkey.pem`, oneTimeLoading: false }] },
        xhttpSettings: { path: settings.path, mode: 'stream-up' },
      },
    }],
    outbounds: [{ protocol: 'freedom', tag: 'direct' }, { protocol: 'blackhole', tag: 'block' }],
  }, null, 2);
  const haproxyNoExisting = `# fabushi-xhttp-split\nbackend xhttp_tls\n    mode tcp\n    server xray 127.0.0.1:${settings.localXrayPort} check\n`;
  return `#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else sudo -n true; SUDO="sudo"; fi
export DEBIAN_FRONTEND=noninteractive
PUBLIC_IP="${settings.originIp}"
if [ -z "$PUBLIC_IP" ]; then PUBLIC_IP="$(curl -4fsS --max-time 15 https://api.ipify.org)"; fi
case "$PUBLIC_IP" in *[!0-9a-fA-F:.]*) echo "无法识别 VPS 公网 IP" >&2; exit 20;; esac

PORT443_OWNER="$($SUDO ss -lntp 2>/dev/null | awk '$4 ~ /:443$/ {print $NF}' | head -1 || true)"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq curl unzip ca-certificates openssl certbot haproxy

for domain in '${settings.upstreamDomain}' '${settings.originDomain}'; do
  for attempt in $(seq 1 30); do
    getent ahostsv4 "$domain" | grep -q "$PUBLIC_IP" && break
    [ "$attempt" -eq 30 ] && { echo "DNS 尚未解析到 $PUBLIC_IP: $domain" >&2; exit 21; }
    sleep 2
  done
done

WAS_APACHE=0; WAS_NGINX=0
$SUDO systemctl is-active --quiet apache2 && { WAS_APACHE=1; $SUDO systemctl stop apache2; } || true
$SUDO systemctl is-active --quiet nginx && { WAS_NGINX=1; $SUDO systemctl stop nginx; } || true
restore_web() { [ "$WAS_APACHE" -eq 1 ] && $SUDO systemctl start apache2 || true; [ "$WAS_NGINX" -eq 1 ] && $SUDO systemctl start nginx || true; }
trap restore_web EXIT
$SUDO certbot certonly --standalone --preferred-challenges http --non-interactive --agree-tos --register-unsafely-without-email --cert-name '${settings.originDomain}' --expand -d '${settings.originDomain}' -d '${settings.upstreamDomain}'
restore_web
trap - EXIT

if ! command -v xray >/dev/null 2>&1; then
  curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | $SUDO bash -s -- install
fi
echo '${encode(xrayConfig)}' | base64 -d > /tmp/fabushi-xray.json
$SUDO install -d -m 0755 /usr/local/etc/xray
$SUDO install -m 0600 /tmp/fabushi-xray.json /usr/local/etc/xray/config.json
rm -f /tmp/fabushi-xray.json
$SUDO xray run -test -config /usr/local/etc/xray/config.json
$SUDO systemctl enable xray
$SUDO systemctl restart xray

DEFAULT_BACKEND=xhttp_tls
if echo "$PORT443_OWNER" | grep -q apache2; then
  DEFAULT_BACKEND=existing_tls
  $SUDO cp -n /etc/apache2/ports.conf /etc/apache2/ports.conf.fabushi-xhttp.bak || true
  $SUDO sed -i -E 's/(Listen[[:space:]]+)443/\\1 9443/g' /etc/apache2/ports.conf
  while IFS= read -r file; do
    $SUDO cp -n "$file" "$file.fabushi-xhttp.bak" || true
    $SUDO sed -i -E 's/(<VirtualHost[^>]*:)443>/\\1 9443>/g' "$file"
  done < <($SUDO grep -RIlE '<VirtualHost[^>]*:443>' /etc/apache2/sites-available || true)
  $SUDO apachectl configtest
  $SUDO systemctl restart apache2
elif echo "$PORT443_OWNER" | grep -q nginx; then
  DEFAULT_BACKEND=existing_tls
  while IFS= read -r file; do
    $SUDO cp -n "$file" "$file.fabushi-xhttp.bak" || true
    $SUDO sed -i -E 's/listen([[:space:]]+)(\[::\]:)?443/listen\\1\\2 9443/g' "$file"
  done < <($SUDO grep -RIlE 'listen[[:space:]]+.*443' /etc/nginx/sites-enabled || true)
  $SUDO nginx -t
  $SUDO systemctl restart nginx
elif echo "$PORT443_OWNER" | grep -q haproxy; then
  $SUDO grep -q 'fabushi-xhttp-split' /etc/haproxy/haproxy.cfg || { echo '443 已由其他 HAProxy 配置占用，已停止以免覆盖' >&2; exit 22; }
elif [ -n "$PORT443_OWNER" ]; then
  echo "443 已被不支持的服务占用: $PORT443_OWNER" >&2
  exit 23
fi

cat > /tmp/fabushi-haproxy.cfg <<'HAPROXY'
global
    log /dev/log local0
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 10s
    timeout client 10m
    timeout server 10m

frontend https_sni_mux
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    use_backend xhttp_tls if { req.ssl_sni -i ${settings.upstreamDomain} ${settings.originDomain} }
    default_backend DEFAULT_BACKEND_VALUE

backend xhttp_tls
    mode tcp
    server xray 127.0.0.1:${settings.localXrayPort} check

backend existing_tls
    mode tcp
    server existing 127.0.0.1:9443 check
# fabushi-xhttp-split
HAPROXY
$SUDO sed -i "s/DEFAULT_BACKEND_VALUE/$DEFAULT_BACKEND/" /tmp/fabushi-haproxy.cfg
$SUDO install -m 0644 /tmp/fabushi-haproxy.cfg /etc/haproxy/haproxy.cfg
rm -f /tmp/fabushi-haproxy.cfg
$SUDO haproxy -c -f /etc/haproxy/haproxy.cfg
$SUDO systemctl enable haproxy
$SUDO systemctl restart haproxy

$SUDO install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
printf '%s\n' '#!/usr/bin/env sh' 'systemctl restart xray' | $SUDO tee /etc/letsencrypt/renewal-hooks/deploy/restart-xray >/dev/null
$SUDO chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/restart-xray
if command -v ufw >/dev/null && $SUDO ufw status | grep -q '^Status: active'; then
  $SUDO ufw allow 80/tcp >/dev/null
  $SUDO ufw allow 443/tcp >/dev/null
  $SUDO ufw --force delete allow ${settings.localXrayPort}/tcp >/dev/null 2>&1 || true
fi

$SUDO systemctl is-active xray haproxy
echo "PUBLIC_IP=$PUBLIC_IP"
echo "XHTTP_READY=1"
`;
}

export function buildRemoteVerificationScript(input = {}, endpoints = {}) {
  const settings = validateSettings(input);
  const config = buildClientConfig(settings, endpoints);
  return `#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
echo '${encode(JSON.stringify(config))}' | base64 -d > /tmp/fabushi-xhttp-client.json
chmod 0600 /tmp/fabushi-xhttp-client.json
xray run -test -config /tmp/fabushi-xhttp-client.json
$SUDO systemd-run --unit=fabushi-xhttp-verify --collect --uid="$(id -un)" xray run -config /tmp/fabushi-xhttp-client.json >/dev/null
cleanup() { $SUDO systemctl stop fabushi-xhttp-verify.service >/dev/null 2>&1 || true; $SUDO systemctl reset-failed fabushi-xhttp-verify.service >/dev/null 2>&1 || true; rm -f /tmp/fabushi-xhttp-client.json; }
trap cleanup EXIT
for attempt in $(seq 1 10); do ss -lnt | grep -q '127.0.0.1:10808' && break; sleep 1; done
curl --socks5-hostname 127.0.0.1:10808 --max-time 40 -fsS https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|colo|tls|http)='
echo XHTTP_VERIFIED=1
`;
}
