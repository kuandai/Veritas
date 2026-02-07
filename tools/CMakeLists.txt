add_executable(veritas_auth_demo
  auth_demo/main.cpp
)

target_link_libraries(veritas_auth_demo
  PRIVATE
    veritas
)

target_compile_features(veritas_auth_demo PRIVATE cxx_std_20)
