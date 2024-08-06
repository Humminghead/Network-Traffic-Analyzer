function(GenerateReport target)
  add_test(
    NAME ${target}
    COMMAND ${target} "--gtest_output=xml:reports/TestReport_${target}.xml"
            "--gtest_filter=*.*"
    WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
endfunction()
