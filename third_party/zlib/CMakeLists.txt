# zlib, vendored unmodified (see VERSION). Only the inflate/deflate core is
# copied; gzip file I/O (gz*.c) and infback.c are not built. gzguts.h is still
# needed because zutil.c includes it unless zlib is built with Z_SOLO, which
# would drop the default allocator.
add_library(sigrelay_zlib STATIC
  adler32.c
  compress.c
  crc32.c
  deflate.c
  inffast.c
  inflate.c
  inftrees.c
  trees.c
  uncompr.c
  zutil.c
)

# SYSTEM keeps zlib.h and zconf.h from raising warnings in code that includes them.
target_include_directories(sigrelay_zlib SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Z_PREFIX makes zconf.h rename every zlib symbol to z_*, so this copy cannot
# collide with a system zlib linked into the same program. It is PUBLIC
# because the library and every file that includes zlib.h must agree on it.
# z_errmsg already starts with z_ and is not renamed by Z_PREFIX, so it would
# still clash with a static system libz.a; it is internal to zlib (zutil.h)
# and gets its own name for this target only.
target_compile_definitions(sigrelay_zlib
  PUBLIC Z_PREFIX
  PRIVATE z_errmsg=sigrelay_z_errmsg
)

# Upstream sources are never edited to satisfy this project's warning flags,
# so warnings are off for this target only and cannot fail a build that sets
# CMAKE_COMPILE_WARNING_AS_ERROR.
set_target_properties(sigrelay_zlib PROPERTIES COMPILE_WARNING_AS_ERROR OFF)
target_compile_options(sigrelay_zlib PRIVATE -w)
