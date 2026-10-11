# sigrelay
Lightweight SIP and Diameter signaling relay in C

## Build and test

Requires CMake 3.20+, a C11 compiler (gcc or clang) and python3.

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build -LE quarantine --output-on-failure
```

Each test case is its own ctest test (listed in `tests/test_list.h`); tests in `tests/quarantine.cmake` are excluded by `-LE quarantine`.

Static analysis runs in CI with cppcheck and clang-tidy (configured in `.clang-tidy`); see `.github/workflows/ci.yml` for the exact commands.

## Upstream pools and the route cache

`include/sigrelay/upstream.h` picks the SIP next hop for a destination from a pool of candidates.

- **Pool** (`sigrelay_upstream_pool`): up to 16 `host[:port]` members, each with a weight from 1 to 100. `sigrelay_upstream_select` hands out healthy members in weighted round-robin order, so a member with weight 3 is picked three times per round, interleaved with the others. It returns `SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY` when every member is down.
- **Health checks**: the caller probes members (an OPTIONS ping, for example) and reports each result with `sigrelay_upstream_mark_probe`. After `max_failures` consecutive failures a member is marked down; one success brings it back. `sigrelay_upstream_probe_due` tells the caller when to probe next: every `probe_interval_ms` while healthy, four times less often while down.
- **Route cache** (`sigrelay_upstream_cache`): eight exact-match entries mapping a SIP domain to the next hop last selected for it, so repeated requests for the same domain stick to one hop for `ttl_ms`. Expired entries count as misses; when the cache is full the entry closest to expiry is replaced. Call `sigrelay_upstream_cache_invalidate` when the cached hop goes down.

The library never reads a clock: every call that needs time takes `now_ms` from the caller, so any monotonic millisecond source works.

## Third-party code

sigrelay vendors zlib 1.3.1 in `third_party/zlib` to decode `gzip` and `deflate` SIP message bodies. [`third_party/README.md`](third_party/README.md) lists the vendored libraries and describes how they are managed and upgraded.
