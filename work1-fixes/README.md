# work1-fixes — CVE-2019-20933 修复

本目录是 Work 1 第三部分（真实 CVE 复现 → 根因 → 修复 → 验证）的修复产物。

| 文件 | 说明 |
|---|---|
| `docker-compose.original.yml` | Vulhub 官方靶场原始配置（**有漏洞**），留作对比 |
| `docker-compose.fixed.yml` | 修复后的配置，只改了一行 |

## 修复内容（diff）

```diff
     - INFLUXDB_HTTP_AUTH_ENABLED=true
+    - INFLUXDB_HTTP_SHARED_SECRET=Str0ng-Shared-Secret-For-Work1-2026
     - INFLUXDB_ADMIN_USER=admin
```

## 为什么这一行就能修好

漏洞的关键不是"认证没开"——`INFLUXDB_HTTP_AUTH_ENABLED=true` 一直是开着的，匿名请求确实会被拒
（`unable to parse authentication credentials`）。问题在于 **JWT 的签名密钥是空字符串**：

1. InfluxDB 1.6.6 在 `services/httpd/handler.go` 的 `authenticate()` 里，当 `SharedSecret` 为空时
   **不拒绝启动、也不跳过 JWT 认证，而是把空字符串当成真正的密钥参与校验**。
2. HMAC-SHA256 的签名是 `HMAC(key, header.payload)`。密钥是空字符串时，任何人都能算出同一个签名，
   服务端用同样的空密钥去验，必然通过 —— **认证被短路，而不是被破解**。
3. 因此伪造的 token 里写 `"username":"admin"` 就等于拿到管理员权限：CVSS 3.1 = **9.8 CRITICAL**。

设置非空 `SHARED_SECRET` 之后，服务端必须用这个密钥验签。攻击者不知道密钥，算不出正确签名，
于是返回 `{"error":"signature is invalid"}` + `HTTP 401`。

这不是"加黑名单拦 payload"，而是**恢复 JWT 的安全前提**（密钥只有服务端知道），
所以不存在"换个 payload 就绕过"的问题。

## 官方修复

InfluxDB 1.7.6 起：`shared-secret` 为空时**拒绝启用 JWT 认证并在启动时报错**（fail-fast）。
通用原则：安全配置缺失时必须 **fail closed**（失败关闭），而不是静默降级为放行。

所以生产环境应当「升级到 ≥1.7.6」+「显式配置高强度 `SHARED_SECRET`」双保险：
前者防止运维再犯，后者修补已有部署。

## 验证方法

```bash
# 1. 用修复版配置重建容器
cp work1-fixes/docker-compose.fixed.yml <靶场目录>/docker-compose.yml
cd <靶场目录> && docker compose up -d --force-recreate

# 2. 用空密钥伪造 token 发起攻击 —— 应失败
python poc/forge_token.py            # 输出空密钥签名的 token
curl -s -X POST "http://127.0.0.1:8086/query?db=sample" \
     --data-urlencode "q=show users" -H "Authorization: Bearer <token>"
# 预期：{"error":"signature is invalid"} + HTTP 401

# 3. 用正确密钥签发的 token —— 应成功（回归测试）
python poc/forge_token.py --secret "Str0ng-Shared-Secret-For-Work1-2026"
curl -s -X POST "http://127.0.0.1:8086/query?db=sample" \
     --data-urlencode "q=show users" -H "Authorization: Bearer <token>"
# 预期：{"results":[{"series":[{"columns":["user","admin"],"values":[["admin",true]]}]}]} + HTTP 200

# 4. 原有 admin:admin Basic 认证 —— 应仍然可用（功能未被破坏）
curl -s -X POST "http://127.0.0.1:8086/query?db=sample" \
     --data-urlencode "q=show databases" -u admin:admin
# 预期：数据库列表 + HTTP 200
```

截图见仓库根目录 `docs/E-1_fix_effective.png`、`docs/E-2_regression.png`。
