# XHTTP 上下行分离

这是一个本地小程序：用户完成 AWS、Cloudflare 登录并填写 VPS 的 SSH 信息后，程序会自动搭建并验证 Cloudflare 上行 + CloudFront 下行的 XHTTP 线路。

## 用户需要准备

- 一个托管在 Cloudflare 的域名。
- 一个 AWS 账号；本机安装 AWS CLI 2.32.0 或更高版本。
- 一台 Ubuntu/Debian VPS，以及 root 或免密 sudo 的 SSH 账号。
- Cloudflare OAuth，或具备以下权限的 API Token：
  - Zone / Zone / Read
  - Zone / DNS / Edit
  - Zone / Zone Settings / Edit

建议使用 SSH 私钥或 ssh-agent。密码只会放进当次 `ssh` 子进程的环境，不会写进状态文件或部署结果。

## 一键流程

1. 检查 AWS、Cloudflare 与 SSH。
2. 创建两个临时 DNS-only A 记录。
3. 通过 SSH 安装 Xray、Certbot 与 HAProxy并签发双域名证书。
4. Xray 只监听 VPS 本机 `127.0.0.1:8443`；公网 `443` 由 HAProxy 按 SNI 分流。
5. 如果 Apache/Nginx 已占用 `443`，备份其配置并迁移到本机 `9443`，HAProxy 继续转发原有 HTTPS 流量。
6. 将上行域名切换为 Cloudflare 代理，源站域名保持 DNS-only；启用 Full TLS 和 gRPC。
7. 创建或更新 CloudFront：HTTPS 443 回源、允许全部方法、启用 gRPC、禁用缓存和压缩、不启用 WAF。
8. 等待 CloudFront 部署，然后在 VPS 启动一次临时 Xray 客户端并真实访问公网。
9. 验证成功后输出 VLESS 导入链接和完整 Xray JSON。

## 安全与恢复

- CloudFront 是按量计费服务；程序不会启用 AWS WAF。
- SSH 主机密钥使用 `accept-new`：首次记录，后续遇到密钥变化会拒绝连接。
- Apache/Nginx 变更前会生成 `*.fabushi-xhttp.bak` 备份。
- Xray 配置位于 `/usr/local/etc/xray/config.json`。
- HAProxy 配置包含 `fabushi-xhttp-split` 标记；检测到其他 HAProxy 配置时不会直接覆盖。
- 客户端导入链接包含 UUID，不能公开分享。

## 本地测试

```bash
npm test
node scripts/xhttp-split.mjs xhttp_status
```
