# 构建指南

依赖链：**Go（构建 BoringSSL）→ BoringSSL → lsquic → 本项目**。vendored lsquic 4.7.0 的 IETF QUIC 加密层**硬绑 BoringSSL 的 `EVP_AEAD` API**（`LSQUIC_LIBSSL=OPENSSL` 只切 TLS 层、切不动 crypto 层，已被证实不兼容），所以必须构建 BoringSSL；而 BoringSSL 的 `err_data.c` 由 Go 脚本生成，**必须装 Go**。

## 前置依赖（macOS / Homebrew）

```bash
brew install go          # BoringSSL 构建必需
brew install cmake spdlog toml11 catch2   # 项目依赖（asio 是 header-only，已在 /opt/homebrew/include）
```

## 1. 构建 BoringSSL

```bash
cmake -S third_party/boringssl -B third_party/boringssl/build -DCMAKE_BUILD_TYPE=Release
cmake --build third_party/boringssl/build -j$(sysctl -n hw.ncpu)
# 产物：third_party/boringssl/build/libssl.a、libcrypto.a
```

## 2. 构建 lsquic（对 BoringSSL）

```bash
cmake -S third_party/lsquic -B third_party/lsquic/build \
    -DLSQUIC_LIBSSL=BORINGSSL \
    -DBORINGSSL_INCLUDE=$PWD/third_party/boringssl/include \
    -DBORINGSSL_LIB_ssl=$PWD/third_party/boringssl/build/libssl.a \
    -DBORINGSSL_LIB_crypto=$PWD/third_party/boringssl/build/libcrypto.a \
    -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=OFF
cmake --build third_party/lsquic/build -j$(sysctl -n hw.ncpu)
# 产物：third_party/lsquic/build/src/liblsquic/liblsquic.a
```

> ⚠️ 若曾用其他 TLS 配置构建过 lsquic，先 `rm -rf third_party/lsquic/build` 清缓存，否则旧的 `LIBSSL_*` 变量残留会让 `BORINGSSL_*` 失效。

## 3. 构建项目

```bash
cmake -S . -B build
cmake --build build -j$(sysctl -n hw.ncpu)
# 产物：build/ebpf-quic-proxy、build/proxy_tests
```

## 4. 测试

```bash
./build/proxy_tests          # 单元测试（codec）
./build/ebpf-quic-proxy proxy.toml   # 运行代理
```

## 常见坑

| 症状 | 原因 | 处理 |
|---|---|---|
| `openssl/aead.h not found` / `EVP_AEAD_CTX` | 尝试用 OpenSSL 编 lsquic | lsquic 硬绑 BoringSSL，换 `-DLSQUIC_LIBSSL=BORINGSSL` |
| `BORINGSSL_*` 变量 "not used by project" | lsquic build 缓存残留旧 `LIBSSL_*` | 删 `third_party/lsquic/build` 重配 |
| BoringSSL 构建报 Go 相关错误 | 没装 Go | `brew install go` |
| `bind: Address already in use` | 端口被其他进程占用（如 java） | 换 `listen.port` |
| H3 客户端报 `header field is not lower-case` | 响应头未小写 | 已修复：`async_send_headers` 强制小写（RFC 9114 §4.2） |
