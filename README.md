# 企业门户：本地登录撤销 + SSRF 防护报告下载

两个安全能力的一体化本地演示（FastAPI + PyJWT + SQLite + httpx + dnspython）：

1. **Back-Channel Logout**：员工在统一身份源退出后，门户撤销其本地登录（已有会话立即失效、在途登录不得建立会话、较晚的登录不受影响）。
2. **SSRF 防护的报告下载**：支持人员从供应商提供的 URL 下载诊断报告，同时防止下载功能被用于探测内网。

全部组件均在本地容器内运行，**演示无需公网**：内置本地权威 DNS、供应商报告服务和内网诱饵服务。

## 架构

```
                            Docker 网络（两个隔离网段）
   reports  172.31.10.0/24（门户唯一允许出站的网段）        intranet 172.31.20.0/24（内网）
  ┌───────────────────────────────────────────────┐        ┌────────────────────────────┐
  │ dns        172.31.10.53  本地权威 DNS (UDP/53) │        │ decoy 172.31.20.66 内网诱饵 │
  │ vendor     172.31.10.10  供应商报告服务 :8080  │        │  （记录所有抵达的请求，演示  │
  │ idp        172.31.10.20  身份源 :9000          │        │   中该列表必须始终为空）     │
  │ portal1    172.31.10.11  门户副本 :8000        │◄──────►│                            │
  │ portal2    172.31.10.12  门户副本 :8000        │ 同时接入 │                            │
  └───────────────────────────────────────────────┘  两个网段└────────────────────────────┘
        门户出站策略（启动时固定）：CIDR=172.31.10.0/24  端口=80,8080
        DNS=172.31.10.53  跳转≤3  总时限=5s  正文≤1MiB
```

两个门户容器同时接入两个网段（因此诱饵在网络层可达），但 fetcher 的固定出站 CIDR 只包含 `172.31.10.0/24`，所以 `172.31.20.0/24` 上的任何主机都不可能经 `POST /reports/download` 被访问。

## 快速开始

```bash
docker compose up --build
```

| 服务 | 主机端口 | Swagger UI |
|---|---|---|
| 本地 DNS（管理 API） | 1054 | http://localhost:1054/docs |
| 供应商报告服务 | 8080 | http://localhost:8080/docs |
| 内网诱饵（管理 API） | 8090 | http://localhost:8090/docs |
| IdP 身份源 | 9000 | http://localhost:9000/docs |
| 门户副本 1 | 8001 | http://localhost:8001/docs |
| 门户副本 2 | 8002 | http://localhost:8002/docs |

DNS 的 UDP/53 发布在主机端口 **1053**。所有可调用入口都在各服务的 `/docs`。

## 报告下载 API（`POST /reports/download`）

- **认证**：复用现有会话，`Authorization: Bearer <session_id>`（与 `/me` 同一套随机凭证）；无凭证返回 401，不会发起任何出站请求。
- **请求体**：`{"url": "http://vendor.reports.local:8080/reports/diagnostic.txt"}`
- **成功响应**：完整正文以附件返回（`Content-Disposition: attachment; filename="..."`），媒体类型取自上游 `Content-Type`；不返回上游的任何 `Content-Disposition`。
- **失败语义**：策略违规 → 400；策略通过但上游失败 → 502；5 秒总预算耗尽 → 504。**任何失败都不返回部分正文**。

### 出站安全保证（每条都在初始请求和每次跳转时重新执行）

1. **仅支持无用户信息的 HTTP URL**：只接受 `http://`（拒绝 https/file/gopher 等）；带 userinfo（`user:pass@host`）的 URL 直接拒绝；主机只接受 IPv4 字面量或可解析为 A 记录的域名，IPv6/IDN 拒绝。
2. **DNS 服务器由启动配置固定**：使用 dnspython 且 `configure=False`，完全不读容器 `/etc/resolv.conf`，只查询 `EGRESS_DNS_SERVERS`。
3. **全部地址逐一核对**：一次解析返回的**所有** A 记录都必须落在 `EGRESS_ALLOWED_CIDRS` 内、端口必须在 `EGRESS_ALLOWED_PORTS` 内；任一地址越界即整体拒绝。
4. **连接地址钉死、保留原 Host、不再二次解析**：TCP 连接只发往本次核准的地址（`http://<已核准IP>:<port><path>`），请求头 `Host` 保留原始域名；域名绝不再交给 HTTP 客户端/OS 解析器，DNS rebinding 没有可乘之机。
5. **跳转**：手工处理 301/302/303/307/308，最多跟随 **3 次**；每个跳转目标重新走完整的 scheme/userinfo/DNS/CIDR/端口 校验；相对跳转按当前 hop 的 URL 解析。
6. **总时限 5 秒**：单一单调钟预算覆盖 DNS、连接、所有跳转和正文读取，超时即 504。
7. **正文上限 1 MiB**：按**解压后**字节计数（压缩炸弹同样拦截），超限即中止并丢弃已缓冲内容。
8. **不转发门户身份、请求间不共享 Cookie**：每跳新建 `httpx.Client`，无 Cookie jar、`trust_env=False`（忽略容器内代理等环境变量）、不继承门户请求的任何头；只发固定的 `Host` 与 `User-Agent`。

### 一键演示（正常下载 / 跳转内网 / DNS rebinding）

```bash
./scripts/report-demo.sh          # 需要 curl、jq、python3+dnspython
```

脚本演示并断言：

| 步骤 | 场景 | 预期 |
|---|---|---|
| 2 | 无会话下载 | 401 |
| 3 | 正常供应商报告 | 200，附件含完整正文 |
| 4 | 供应商 302 跳转到内网（同端口，纯粹 CIDR 拦截） | 400，**诱饵零请求** |
| 5 | DNS 第一次返回获准地址、之后换成诱饵地址（rebinding） | 200 且只发生 **1 次** DNS 查询（钉死首个核准地址），直接复查 DNS 可见后续应答已是诱饵，**诱饵零请求** |
| 6 | 一次返回多个 A 记录、其中一个是内网 | 400（全部地址都核对） |
| 7 | https / userinfo / 非允许端口 / 内网域名 / 内网 IP 字面量 | 全部 400 |
| 8 | 跳转循环（>3 跳）、慢响应（>5s）、2 MiB 正文 | 400 / 504 / 502，均无部分正文 |
| 9 | 回显上游收到的头 | 无 `Authorization`、无 `Cookie`，Host 为原域名 |
| 10 | 最终核对 | 诱饵请求数 = 0，并输出完整 DNS 查询日志 |

> Rebinding 的关键证据不是"返回 400"，而是：门户对该域名**只解析一次**，验证首个获准地址后直接钉死该地址连接；DNS 随后把应答换成诱饵地址也无法影响连接（脚本通过 DNS 查询日志与直接复查两种方式证明）。

### 在 /docs 手动调用

1. IdP（:9000）`POST /authorize` → 复制 `code`；门户（:8001）`POST /login` → 复制 `session_id`，点右上角 **Authorize** 粘贴。
2. 门户 `POST /reports/download`，body 例如：
   - 正常：`{"url":"http://vendor.reports.local:8080/reports/diagnostic.txt"}`
   - 跳内网：`{"url":"http://vendor.reports.local:8080/redirect/internal"}`
   - Rebinding：`{"url":"http://rebind.reports.local:8080/reports/diagnostic.txt"}`
3. 诱饵 `GET http://localhost:8090/requests` 确认 `count` 始终为 0；DNS `GET http://localhost:1054/queries` 查看每个请求触发的 DNS 查询。

## 配套本地服务

| 服务 | 关键路径 |
|---|---|
| `dns/` | 基于文件（`records.json`）的本地权威 DNS，支持 UDP/TCP 53；`rebind_a` 类型按**客户端**轮转应答（首次获准地址、其后诱饵地址）以离线模拟 rebinding；HTTP 管理 API 提供 `/records`、`/queries`、`/queries/clear` |
| `vendor/` | `/reports/diagnostic.txt` 正常报告；`/redirect/internal` 302 到内网；`/redirect/loop` 超 3 跳；`/redirect/ok` 合法单跳；`/too-large` 2 MiB；`/slow` 8 秒慢响应；`/echo` 回显请求头 |
| `decoy/` | 记录所有抵达请求（管理路径除外），`GET /requests` 查看、`POST /requests/clear` 清零；演示成功的标准是该列表始终为空 |

## Back-Channel Logout（原有能力，保持不变）

- **身份 JWT**（RS256）：`sub`、`sid`、`iat`、`exp`、`purpose="identity"`；**注销 JWT**：`iat`、`exp`、`jti`、`purpose="logout"` 及唯一目标 `sid`/`sub`。
- 门户按目标持久化**最大注销 iat**（只升不降）；身份 JWT 的 `iat <=` 该值的：已有会话删除、在途登录 409 拒绝；较晚的登录放行。
- 两个门户进程共享一个 SQLite（WAL + `BEGIN IMMEDIATE`），登录/注销临界区跨进程互斥；重复 `jti` 为幂等 no-op。
- 完整演示：`./scripts/demo.sh`（并发串行等价性：`./scripts/stress-test.sh`）。

## 配置（环境变量，均为启动时固定）

门户新增（报告下载）：

| 变量 | 默认（Compose 值） | 含义 |
|---|---|---|
| `EGRESS_ALLOWED_CIDRS` | `172.31.10.0/24` | 允许出站的 IPv4 CIDR，逗号分隔，至少一个 |
| `EGRESS_ALLOWED_PORTS` | `80,8080` | 允许出站端口，逗号分隔 |
| `EGRESS_DNS_SERVERS` | `172.31.10.53` | 固定 DNS 服务器（仅 IPv4），逗号分隔 |
| `EGRESS_DNS_PORT` | `53` | DNS 端口 |
| `EGRESS_MAX_REDIRECTS` | `3` | 最大跳转次数 |
| `EGRESS_TOTAL_TIMEOUT` | `5` | 全链路总时限（秒，含 DNS 与所有跳转） |
| `EGRESS_MAX_BODY_BYTES` | `1048576` | 正文上限（字节，按解压后计） |

门户原有：`IDP_PUBLIC_KEY_PATH`、`IDP_ISSUER`、`IDP_AUDIENCE`、`IDP_TOKEN_URL`、`PORTAL_DB_PATH`、`IDP_TOKEN_EXCHANGE_TIMEOUT`、`TOKEN_CLOCK_LEEWAY`。
DNS：`DNS_RECORDS_PATH`、`DNS_BIND_HOST`、`DNS_BIND_PORT`、`DNS_HTTP_PORT`。供应商：`VENDOR_INTERNAL_REDIRECT_BASE`、`VENDOR_DEMO_BODY_BYTES`。

## 说明与边界

- `deploy/keys/` 为演示专用开发密钥；生产应挂载真实密钥并限制私钥访问。
- 策略配置在进程启动时解析一次并校验（非法 CIDR/端口/DNS 地址会导致启动失败），不存在按请求修改策略的接口；`GET /debug/egress-policy` 只读展示当前固定策略。
- 本地无 Docker 时的等价验证：按 Compose 的 IP/端口规划用 uvicorn 分别启动各服务（DNS 可用 127/8 回环地址模拟两个网段），再运行 `scripts/report-demo.sh`。
