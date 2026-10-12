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

`include/sigrelay/upstream.h` picks the SIP next hop for a destination from a pool of candidates and remembers recent choices per domain. Pools and caches are fixed-size structs owned by the caller; nothing is allocated. The library never reads a clock: every call that needs time takes `now_ms` from the caller, so any monotonic millisecond source works. Output parameters are written only when a call returns `SIGRELAY_UPSTREAM_OK`.

### Pool members

`sigrelay_upstream_pool_init(pool, probe_interval_ms, max_failures)` empties the pool. `probe_interval_ms` must be 1 to 600000 (10 minutes) and `max_failures` 1 to 16.

`sigrelay_upstream_member_add(pool, name, name_len, weight)` appends a healthy member that takes part in the current round straight away. Names are meant to be `host[:port]`, but they are not parsed: the only checks are a length of 1 to 255 bytes and printable ASCII without spaces, so `a:b:c` is accepted. Names are passed as pointer plus length and compared byte for byte, so `Host` and `host` are different members. Weight is 1 to 100, and a pool holds at most 16 members. Checks run in this order and the first failure is returned with the pool unchanged: `INVALID_NAME`, `DUPLICATE`, `POOL_FULL`, `INVALID_WEIGHT`. A bad weight on a full pool therefore reports `POOL_FULL`. There is no update call; to change a weight, remove the member and add it again.

`sigrelay_upstream_member_remove` shifts later members down, so a next hop returned by an earlier `select` may then point at a different member. Copy it first if you need it.

`sigrelay_upstream_select(pool, &next_hop)` returns healthy members in weighted round-robin order. Each round a member is picked up to its weight times, interleaved with the others. A new round starts when no healthy member has picks left. `next_hop` points into the pool. The call returns `SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY` when the pool is empty or every member is down. **Known issue:** the selection scan in `src/upstream.c` never reaches the last slot of the pool (the most recently added member), so that member is never returned and a single-member pool always returns `SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY`.

### Health checks

The library does not send probes. The caller probes each member (an OPTIONS ping, for example) and reports the result with `sigrelay_upstream_mark_probe(pool, name, name_len, success, now_ms)`, which also records `now_ms` as the member's last probe time.

- A failure adds one to the member's consecutive-failure count. When the count reaches `max_failures`, the member is marked down and is no longer selected. Below the threshold it stays healthy and selectable.
- A success resets the count to zero and marks the member healthy. A member that recovers mid-round is selected again from the next round.

`sigrelay_upstream_probe_due(pool, name, name_len, now_ms, &due)` sets `due` to 1 when at least `probe_interval_ms` has passed since the last probe of a healthy member, or `4 * probe_interval_ms` (`SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR`) for a member that is down. It also sets `due` when `now_ms` is earlier than the last probe, which happens if the clock went backwards. A member that has never been probed counts as last probed at 0.

### Route cache

`sigrelay_upstream_cache` maps a SIP domain to the next hop last selected for it, so repeated requests for one domain stick to one hop. The usual flow is `sigrelay_upstream_cache_lookup`; on `SIGRELAY_UPSTREAM_ERR_CACHE_MISS`, call `sigrelay_upstream_select` and then `sigrelay_upstream_cache_store`.

- **TTL:** `sigrelay_upstream_cache_init(cache, ttl_ms)` takes 1 to 3600000 ms (1 hour). `store` sets an entry to expire at `now_ms + ttl_ms`. Lookups do not extend that time. Storing the same domain again replaces the hop and restarts the TTL. `store` checks the next hop with the same rules as member names but does not check that it belongs to any pool.
- **Hit or miss:** domains are 1 to 253 characters of letters, digits, `-` and `.`, with no port. They are matched exactly but case-insensitively, with no fallback to a parent domain. A lookup is a hit while `now_ms` is before the entry's expiry. It then returns the hop as a pointer into the cache, which a later `store` or `invalidate` can overwrite. A missing entry, or one whose expiry `now_ms` has reached, is `SIGRELAY_UPSTREAM_ERR_CACHE_MISS`. Lookups never modify the cache.
- **Eviction:** the cache has 8 slots. A new domain takes a free or expired slot first. When all 8 entries are live, the one closest to expiry is overwritten without notice.
- **Invalidation:** the cache does not consult the pool, so a hit can return a hop that has since gone down or been removed. When that happens, call `sigrelay_upstream_cache_invalidate(cache, domain, domain_len)` for each domain that maps to the hop. Invalidation is by domain only. It clears the entry, expired or not, and returns `SIGRELAY_UPSTREAM_ERR_NOT_FOUND` if the domain has no entry.

### Error codes

`sigrelay_upstream_strerror` returns a short description for logs. Function names below drop the `sigrelay_upstream_` prefix.

| Status | Returned by | Meaning for the caller |
|---|---|---|
| `SIGRELAY_UPSTREAM_OK` | all | Success. |
| `SIGRELAY_UPSTREAM_ERR_INVALID_ARG` | all | A required pointer is NULL, or an init parameter is out of range. This is a caller bug and nothing changed. `mark_probe` reads the pool before its NULL check, so a NULL pool crashes there instead. |
| `SIGRELAY_UPSTREAM_ERR_INVALID_NAME` | `member_add`, `cache_lookup`, `cache_store`, `cache_invalidate` | The member name, next hop or domain failed the length or character checks. The input was rejected and nothing changed. |
| `SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT` | `member_add` | Weight is 0 or above 100. |
| `SIGRELAY_UPSTREAM_ERR_DUPLICATE` | `member_add` | A member with that exact name already exists. It keeps its weight and health state. |
| `SIGRELAY_UPSTREAM_ERR_POOL_FULL` | `member_add` | The pool already has 16 members. Remove one first. |
| `SIGRELAY_UPSTREAM_ERR_NOT_FOUND` | `member_remove`, `mark_probe`, `probe_due`, `cache_invalidate` | No member has that name, or the domain has no cache entry. After `cache_invalidate` this is safe to ignore. |
| `SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY` | `select` | Nothing can be selected. Fail the request or use a fallback route. |
| `SIGRELAY_UPSTREAM_ERR_CACHE_MISS` | `cache_lookup` | There is no live entry. Select from the pool and store the result. |

## Third-party code

sigrelay vendors zlib 1.3.1 in `third_party/zlib` to decode `gzip` and `deflate` SIP message bodies. [`third_party/README.md`](third_party/README.md) lists the vendored libraries and describes how they are managed and upgraded.
