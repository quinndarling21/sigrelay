# Tests listed here get the ctest label "quarantine" and are excluded from CI,
# which runs `ctest -LE quarantine`. Quarantine is only for tests classified as
# flaky by the ci-triage process (.cursor/skills/ci-triage/SKILL.md).
#
# Every entry must link to the triage comment that justified it, and the entry
# is removed once the flakiness is fixed:
#
#   set(SIGRELAY_QUARANTINED_TESTS
#     sip_parses_invite  # https://github.com/quinndarling21/sigrelay/pull/<n>#issuecomment-<id>
#   )
set(SIGRELAY_QUARANTINED_TESTS
)
