# Third-party code

Code that sigrelay builds but does not own is vendored here, one directory per library.

| Library | Version | License | Upstream | Used for |
|---------|---------|---------|----------|----------|
| [zlib](zlib/) | 1.3.1 | zlib (`zlib/LICENSE`) | https://zlib.net/ | decoding `gzip` and `deflate` SIP message bodies (`src/sip_body.c`) |

## Layout

Each library lives in `third_party/<lib>/` and contains:

- the upstream `LICENSE`, copied verbatim;
- the upstream source files the build needs, unmodified;
- `VERSION`: name, version, upstream release URL, SHA-256 of the release tarball, license, the list of copied files, and local modifications (always "none");
- `CMakeLists.txt`: the build target, maintained in this repository.

## Rules

- Source comes only from the official upstream release tarball, verified against the SHA-256 that upstream publishes. Files from mirrors, forks or upstream development branches are not used.
- Upstream files are never edited. Build differences go in the library's `CMakeLists.txt` instead; zlib, for example, is built with `Z_PREFIX` so it cannot collide with a system zlib.
- Third-party targets build with warnings disabled and expose their headers as SYSTEM include directories. cppcheck and clang-tidy check only sigrelay's own code in `src` and `include`.
- Every change under `third_party/`, including upgrades, goes through a pull request reviewed by the code owners in `.github/CODEOWNERS`.

## Upgrading a library

1. Download the release tarball from the official upstream site and check its SHA-256 against the value published in the upstream release announcement.
2. Replace the files listed in `third_party/<lib>/VERSION` with the ones from the tarball, unmodified. Add any new file the build needs to that list and to `third_party/<lib>/CMakeLists.txt`, and remove files the new release no longer has.
3. Update the version, release URL and SHA-256 in `VERSION`, and the version in the table above.
4. Confirm that the copied files match the extracted tarball with `diff -r`, ignoring `VERSION` and `CMakeLists.txt`.
5. Build with gcc and clang with warnings as errors, run the full test suite, and open a pull request for code-owner review.

When an upgrade is prepared without the release tarball, the pull request updates `VERSION` to the target release and adds the library under "Pending upgrades" below; a maintainer adds the verified release files to that pull request before it merges.

## Pending upgrades

None.
