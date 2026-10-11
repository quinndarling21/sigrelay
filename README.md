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

## Third-party code

sigrelay vendors zlib 1.3.1 in `third_party/zlib` to decode `gzip` and `deflate` SIP message bodies. [`third_party/README.md`](third_party/README.md) lists the vendored libraries and describes how they are managed and upgraded.
