project(DH_CLIENT)
add_executable(${PROJECT_NAME} ./src/main.cpp )
target_link_libraries(DH_CLIENT
        PUBLIC
        DH_LIBRARY_AES DH_LIBRARY_DH)
target_include_directories(DH_CLIENT
        PUBLIC
        ./include)