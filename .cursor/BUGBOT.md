# Review rules for sigrelay

sigrelay parses SIP and Diameter from untrusted peers. Review every change to `src/`, `include/` and `tests/` against the rules below and flag violations as bugs, not style nits. Changes under `third_party/` follow the third-party rules at the end.

## Memory safety
- Flag buffer overflows and over-reads: any read or write that is not preceded by a bounds check against the remaining buffer length.
- Flag use-after-free, double free, and pointers or `sigrelay_str` views that outlive the buffer they point into.
- Flag leaks on every error path; each early return must release what was acquired before it.
- Flag variable-length arrays and unbounded stack allocation.

## Lengths and offsets from the wire
- Every SIP and Diameter length or offset taken from the wire must be bounds-checked before use: SIP Content-Length and CSeq, the Diameter 24-bit message length, the 24-bit AVP length, the Vendor-ID header extension, and AVP padding to a 4-byte boundary.
- The Diameter message length must be at least the header size, a multiple of 4, and no larger than the received buffer. An AVP length must cover its own header (8 bytes, or 12 with the V bit) and fit in the remaining bytes, and its padding must fit as well.
- Flag integer overflow or underflow in length math: `offset + len` compared after the fact, unsigned subtraction that can wrap, narrowing from `size_t` to a smaller type without a range check, and decimal parsing without an overflow check.

## Suppressions
- No silent suppressions. Every `// cppcheck-suppress <id>` and every `// NOLINT(<check>)` must name the specific id or check and carry an inline justification explaining why the code is correct.
- Flag bare `NOLINT`, `NOLINTNEXTLINE` without a check name, new entries in `.clang-tidy` that disable checks without a justification comment, and new cppcheck `--suppress` flags in CI.

## Tests
- New or changed parser paths need malformed-input tests (truncated input, oversized and undersized lengths, invalid characters, boundary values) in the same change.
- Flag any weakened or deleted test: removed assertions, loosened expected values, deleted test cases, entries removed from `tests/test_list.h`, or tests skipped or disabled.
- Flag new entries in `tests/quarantine.cmake` that do not link to the triage comment that justified them.

## Third-party code
- Flag every change under `third_party/` as High severity: "third-party code change: needs code-owner review; confirm upstream source, version and license".
- Do not report style or static-analysis findings inside the unmodified upstream files under `third_party/`. For those files, only check whether they match the upstream release declared in `third_party/<lib>/VERSION` (version, release tarball and SHA-256), and flag any file that does not.
