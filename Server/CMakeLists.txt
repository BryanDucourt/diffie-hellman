project(DH_SERVER)
add_executable(${PROJECT_NAME} ./src/main.cpp)
target_link_libraries(DH_SERVER
        PUBLIC
        DH_LIBRARY_AES DH_LIBRARY_DH)
