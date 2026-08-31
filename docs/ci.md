# CI 规范

> 目标：一次拉取、一杆子把代码拉到可运行状态，验证 **构建 + 单测 + 端到端冒烟 + 优雅关闭**。构建步骤以 [build.md](build.md) 为准，本文定义**顺序、验证清单、平台差异与 CI 特有约束**。

## 构建链（顺序固定）

```
Go ─▶ BoringSSL ─▶ lsquic（打 A+B interop 补丁）─▶ 项目（C++17）
```

1. **BoringSSL**（需要 Go）：`third_party/boringssl/build/libssl.a + libcrypto.a`
2. **lsquic**（对 BoringSSL）：
   ```bash
   bash scripts/ensure_lsquic_patch.sh   # 必须先于 lsquic 构建：应用 A+B interop 补丁
   cmake -S third_party/lsquic -B third_party/lsquic/build \
       -DLSQUIC_LIBSSL=BORINGSSL -DBORINGSSL_INCLUDE=... \
       -DBORINGSSL_LIB_ssl=... -DBORINGSSL_LIB_crypto=... \
       -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=OFF
   cmake --build third_party/lsquic/build -j
   ```
   > **补丁顺序是硬性约束**：若先编 lsquic 后打补丁，`liblsquic.a` 由未打补丁源码编出——项目的 `lsquic-patch-guard`（CMake target）会在链接时报错，但更省事的是 CI 一开始就按上面的顺序跑。
3. **项目**：`cmake -S . -B build && cmake --build build -j`
   - 构建钩子 `lsquic-patch-guard` 自动生效（每次链接 lsquic 的目标前校验补丁已应用 + `.a` 不陈旧）。

## 验证清单（全绿才算过）

| # | 步骤 | 命令 / 期望 |
|---|---|---|
| 1 | 单元测试 | `./build/proxy_tests` → `All tests passed (140 assertions in 24 test cases)` |
| 2 | 补丁守卫自检 | `bash scripts/ensure_lsquic_patch.sh` → `liblsquic.a is up to date` |
| 3 | TCP e2e | 起 H1 后端 + 代理 → `curl http://127.0.0.1:PORT/` → 200 |
| 4 | H3 e2e（需 http3 版 curl） | `curl -k --http3-only https://127.0.0.1:PORT/` 与 `https://localhost:PORT/`（无 SNI + 有 SNI）→ 200 |
| 5 | 优雅关闭冒烟 | SIGINT 代理 → exit 0；客户端读到 EOF（无 RST）；日志含 `graceful shutdown` → `GOAWAY`/`CONNECTION_CLOSE` → `stopping all io_contexts` |

## 平台差异

| 项 | macOS（开发） | Linux（CI） |
|---|---|---|
| http3 版 curl | `brew install curl`（路径 `/opt/homebrew/opt/curl/bin/curl`，ngtcp2 1.19） | 需自带/构建 ngtcp2+curl（或临时跳过第 4 步） |
| `SO_REUSEPORT` 分片 | 不分发（多绑定、流量全投一个 socket） | 按 4 元组分发 |
| 依赖 | `brew install go cmake spdlog toml11 catch2` | 系统包 + Go 1.20+ |

> 代理本身是 **Model A（1 ingress + N co-located worker）**，不依赖 `SO_REUSEPORT` 分片——macOS 与 Linux 行为一致（详见 design-quic-demux.md）。QUIC 迁移安全由 CID 路由保证，与内核无关。

## CI 特有约束：`third_party/` 是 gitlink 子模块（已落地）

`third_party/lsquic`、`third_party/boringssl` 是**真 gitlink 子模块**（`.gitmodules`，pinned 到当前 vendored commit）。CI `actions/checkout@v4 with: { submodules: recursive }` 一步拉到。补丁**不 commit 进子模块**——仍由 `ensure_lsquic_patch.sh` 在构建时应用（子模块检出的是未打补丁的上游 commit）。

开发机注意：
- 子模块工作树**永远带 A+B 补丁 + build/，在 `git status` 里显脏**——这是正常的。不想看噪音：
  ```bash
  git config submodule.third_party/lsquic.ignore all
  git config submodule.third_party/boringssl.ignore all
  ```
- **不要在本机跑 `git submodule update`**：会把 lsquic 重置到未打补丁的 pinned commit，`ensure_lsquic_patch.sh` 会重新应用并逼你重建 `.a`。更新子模块 = `git -C third_party/lsquic checkout <新commit>` + `git add third_party/lsquic`。
- 子模块 commit 必须与 `docs/lsquic-4.7.0-http3-interop-a-b.patch` 的上下文匹配（当前 pinned v4.7.0）。

## GitHub Actions 工作流（已落地）

`.github/workflows/ci.yml`——push 到 main 或 PR 即跑，`ubuntu-24.04` + `macos-14` 矩阵：

| 步骤 | 说明 |
|---|---|
| checkout (submodules: recursive) | 拉 third_party gitlink |
| setup-go 1.25 | **BoringSSL `go.mod` 要求 ≥ 1.25.0**（比 GH runner 默认新，必须显式 pin） |
| 依赖 | macOS: `brew install cmake spdlog toml11 catch2 curl`；Ubuntu: `apt install cmake libspdlog-dev libtoml11-dev catch2-3`（**Catch2 v3**，项目测试用 `catch2/catch_test_macros.hpp`） |
| 构建链 | BoringSSL → `ensure_lsquic_patch.sh` → lsquic → 项目 |
| 单测 + patch guard 自检 | `proxy_tests` + `bash scripts/ensure_lsquic_patch.sh` |
| TCP e2e | 起 H1 后端 + 代理 → curl 200，SIGINT 优雅退出（两平台） |
| H3 e2e | **仅 macOS**（brew curl 带 ngtcp2/nghttp3；Ubuntu 系统 curl 没有）：CI 内生成自签证书 → `curl --http3-only` 对 `127.0.0.1`（无 SNI）与 `localhost`（SNI）均 200 |

> 若以后要在 Ubuntu 也跑 H3 e2e：apt 装不了 http3 版 curl，需要自己编 ngtcp2/nghttp3/curl，或在容器里用 `ghcr.io/...` 带 http3 的 curl 镜像。

## 本地一键（替代 CI 的最小脚本）

```bash
bash scripts/ensure_lsquic_patch.sh && \
cmake -S third_party/lsquic -B third_party/lsquic/build ... && \
cmake --build third_party/lsquic/build -j && \
cmake -S . -B build && cmake --build build -j && \
./build/proxy_tests
```
