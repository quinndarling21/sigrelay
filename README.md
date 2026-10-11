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

| Path | Project | Version | License |
|------|---------|---------|---------|
| `vendor/zlib` | [zlib](https://zlib.net/) | 1.3.1 | zlib (`vendor/zlib/LICENSE`) |

zlib decodes `gzip` and `deflate` SIP message bodies. Its files are copied unmodified from the upstream release tarball and built as the static library `sigrelay_zlib` with warnings disabled; cppcheck and clang-tidy check only `src` and `include`. `vendor/zlib/VERSION` records the version, the tarball URL and SHA-256, and the list of copied files.

To update zlib:

1. Download the new release tarball from https://zlib.net/ and check its SHA-256 against the published value.
2. Replace the files listed in `vendor/zlib/VERSION` with the ones from the tarball, unmodified. Add any new source file the library needs to that list and to `vendor/zlib/CMakeLists.txt`.
3. Update the version, tarball URL and SHA-256 in `vendor/zlib/VERSION`, and the version in the table above.
4. Build and run the full test suite with gcc and clang.
