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

## ⚠️ CI 特有约束：`third_party/` 未被仓库跟踪

`third_party/`（vendored lsquic + BoringSSL）**在 `.gitignore` 里**，`git submodule status` 也为空——**不是 gitlink 子模块**。因此 CI 从仓库检出时 `third_party/` 是**空的**，必须先拉取：

- **方案 A（推荐，改动仓库）**：把 `third_party/lsquic`、`third_party/boringssl` 改为**真 gitlink 子模块**（`git submodule add`），CI `submodules: recursive` 一步到位；补丁仍由 `ensure_lsquic_patch.sh` 在构建时应用。
- **方案 B（不改仓库）**：CI 步骤里按固定 commit 拉取两仓库源码到 `third_party/`（等价于手工 vendor）：
  ```bash
  git clone --filter=blob:none https://github.com/litespeedtech/lsquic.git third_party/lsquic && git -C third_party/lsquic checkout <PINNED_COMMIT>
  git clone --filter=blob:none https://github.com/google/boringssl.git third_party/boringssl && git -C third_party/boringssl checkout <PINNED_COMMIT>
  ```
  注意 lsquic 需与当前 `docs/lsquic-4.7.0-http3-interop-a-b.patch` 对应的版本匹配（补丁对 v4.7.0）。

## 建议的 GitHub Actions 工作流（骨架）

> 落地前先解决上面的 third_party 拉取方式（方案 A 或 B），并把 `PINNED_COMMIT` 填上。

```yaml
name: ci
on: [push, pull_request]
jobs:
  build-test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, macos-14]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        # 若用方案 A：with: { submodules: recursive }
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - name: Install deps
        run: |
          [ "$RUNNER_OS" = "macOS" ] && brew install cmake spdlog toml11 catch2 curl || \
          sudo apt-get update && sudo apt-get install -y cmake libspdlog-dev catch2 \
            && git clone --depth=1 https://github.com/ToruNiina/toml11 /tmp/toml11 && sudo cmake --install /tmp/toml11
      - name: Vendor third_party (方案 B 示例)
        run: |   # 或换用 submodules: recursive
          git clone --filter=blob:none .../lsquic.git third_party/lsquic && git -C third_party/lsquic checkout <PINNED>
          git clone --filter=blob:none .../boringssl.git third_party/boringssl && git -C third_party/boringssl checkout <PINNED>
      - name: Build BoringSSL
        run: cmake -S third_party/boringssl -B third_party/boringssl/build -DCMAKE_BUILD_TYPE=Release && cmake --build third_party/boringssl/build -j
      - name: Patch + build lsquic
        run: |
          bash scripts/ensure_lsquic_patch.sh
          cmake -S third_party/lsquic -B third_party/lsquic/build -DLSQUIC_LIBSSL=BORINGSSL -DBORINGSSL_INCLUDE=$PWD/third_party/boringssl/include -DBORINGSSL_LIB_ssl=$PWD/third_party/boringssl/build/libssl.a -DBORINGSSL_LIB_crypto=$PWD/third_party/boringssl/build/libcrypto.a -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=OFF
          cmake --build third_party/lsquic/build -j
      - name: Build project
        run: cmake -S . -B build && cmake --build build -j
      - name: Unit tests
        run: ./build/proxy_tests
      - name: Patch guard self-check
        run: bash scripts/ensure_lsquic_patch.sh
      # H3 e2e（linux 需要 ngtcp2 curl）与优雅关闭冒烟为可选步，见上表
```

## 本地一键（替代 CI 的最小脚本）

```bash
bash scripts/ensure_lsquic_patch.sh && \
cmake -S third_party/lsquic -B third_party/lsquic/build ... && \
cmake --build third_party/lsquic/build -j && \
cmake -S . -B build && cmake --build build -j && \
./build/proxy_tests
```
