project(DH_MITM)
add_executable(${PROJECT_NAME} ./src/main.cpp)
target_link_libraries(${PROJECT_NAME}
        PUBLIC
        DH_LIBRARY_AES DH_LIBRARY_DH pcap)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        ./include)