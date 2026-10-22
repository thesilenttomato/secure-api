# secure-api

HDU 信息安全实验 Work 1 的 A 部分：一个**默认安全**的 Flask REST API，配套 GitHub Actions 做 SAST + SCA 自动化安全扫描。

## 接口

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| POST | `/auth/login` | 无 | 校验账号密码，成功返回 HS256 签名的 JWT（有效期 30 分钟） |
| GET | `/api/data` | Bearer | 返回留言列表，`count` + `items` |
| POST | `/api/posts` | Bearer | 新建留言，返回 201 |
| GET | `/api/me` | Bearer | 返回当前主体的 `sub` / `login` / `role` |

## 运行

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app\app.py     # 监听 127.0.0.1:5000，首次启动自动建库并写入种子数据
```

种子账号：`alice / Passw0rd!alice`（admin）、`bob`、`carol`。

生产环境必须通过环境变量覆盖 `JWT_SECRET`，默认值仅供本机调试。

## 安全设计（对应 OWASP Top 10）

| 风险 | 处理方式 | 代码位置 |
|---|---|---|
| A01 越权 | 受保护接口统一走 `@jwt_required` 装饰器，未通过校验不进入视图 | `jwt_required()` |
| A02 加密失败 | 口令用 bcrypt（cost 12、每用户随机盐）存储，不存明文、不做自研哈希 | `init_db()` / `login()` |
| A03 注入-SQL | 全部 SQL 使用 `?` 占位符参数化，payload 永远是数据不会是语句 | 所有 `db.execute()` |
| A03 注入-XSS | 入口处 `html.escape(quote=True)` 转义后再落库，配合 `nosniff` + CSP 双重兜底 | `clean()` |
| A07 认证失败 | JWT 校验固定 `algorithms=["HS256"]`（阻断 `alg=none` 与 RS→HS 混淆），强制要求 `exp`/`sub`，区分「过期」与「非法」 | `jwt_required()` |
| A05 配置错误 | 统一安全响应头：`nosniff`、`X-Frame-Options: DENY`、`no-store`、`default-src 'none'` | `security_headers()` |

几处刻意为之的细节：

- `algorithms=[JWT_ALG]` 是**算法白名单**。只写 `jwt.decode(token, secret)` 而不指定算法，攻击者可以伪造 `alg=none` 的 token 或做密钥混淆攻击——这正是本项目 C 部分复现的 CVE-2019-20933 的同类思路。
- 用户不存在时也执行一次 bcrypt 校验，避免通过响应时间差枚举账号。
- 输入统一裁剪 + 长度上限（`clean()`），超长或非字符串一律拒绝，杜绝把畸形数据带进下游。

## CI/CD：GitHub Actions

`.github/workflows/ci.yml`，push 与 PR 时自动触发，job 名 `SAST (bandit) + SCA (pip-audit)`：

1. **Checkout** → **setup-python 3.12**
2. **Install dependencies**：装业务依赖 + `bandit` / `pip-audit`
3. **SAST - bandit**：`bandit -r app -f txt -o reports/bandit.txt -ll`
   静态分析源码，`-ll` 表示只报 medium 及以上。发现中高危问题会让 job 失败。
4. **SCA - pip-audit**：`pip-audit -r requirements.txt`
   对照 OSV / PyPI 漏洞库检查第三方依赖的**已知 CVE**，发现漏洞即失败。
5. **Upload security reports**：`if: always()` 上传 `reports/` 为 artifact，即使扫描失败也能拿到报告文件。

SAST 查的是**自己写的代码**（有没有硬编码密钥、`eval`、弱随机、命令拼接），SCA 查的是**别人写的依赖**（用的库有没有已知漏洞）。两者互补：代码写得再干净，依赖带洞一样会被打穿。

## 目录结构

```
secure-api/
├─ .github/workflows/ci.yml   # SAST + SCA 流水线
├─ app/app.py                 # 全部接口与安全控制
├─ requirements.txt           # 依赖锁定版本
└─ .gitignore                 # 排除 .venv / app.db / reports
```
