foreach(app send_server send_client msg_client msg_server pthread fcntl)
  add_executable(${app} ${app}.c)
  set_target_properties(${app}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests/apps/"
  )
endforeach()

target_link_libraries(pthread ${CMAKE_THREAD_LIBS_INIT})
