add_executable(sigrelay_tests
  test_main.c
  test_sip.c
  test_diameter.c
  test_relay.c
)
target_link_libraries(sigrelay_tests PRIVATE sigrelay)

# test_list.h is the single list of test cases. Each entry is registered as its
# own ctest test so JUnit output reports cases individually.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/test_list.h)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/test_list.h test_list)
string(REGEX MATCHALL "X\\([a-z0-9_]+\\)" test_case_entries "${test_list}")
if(NOT test_case_entries)
  message(FATAL_ERROR "no test cases found in tests/test_list.h")
endif()
foreach(entry IN LISTS test_case_entries)
  string(REGEX REPLACE "^X\\(([a-z0-9_]+)\\)$" "\\1" test_case "${entry}")
  add_test(NAME ${test_case} COMMAND sigrelay_tests ${test_case})
endforeach()

include(${CMAKE_CURRENT_SOURCE_DIR}/quarantine.cmake)
foreach(test_case IN LISTS SIGRELAY_QUARANTINED_TESTS)
  if(NOT TEST ${test_case})
    message(FATAL_ERROR "tests/quarantine.cmake lists unknown test '${test_case}'")
  endif()
  set_tests_properties(${test_case} PROPERTIES LABELS quarantine)
endforeach()
if(SIGRELAY_QUARANTINED_TESTS)
  message(STATUS "Quarantined tests (excluded by ctest -LE quarantine): ${SIGRELAY_QUARANTINED_TESTS}")
endif()
