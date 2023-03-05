project(DH_LIBRARY)
add_library(${PROJECT_NAME}_AES ./src/AES.cpp)
target_include_directories(${PROJECT_NAME}_AES
        PUBLIC ${PROJECT_SOURCE_DIR} ./include)
add_library(${PROJECT_NAME}_DH ./src/DH.cpp)
target_include_directories(${PROJECT_NAME}_DH
        PUBLIC ${PROJECT_SOURCE_DIR} ./include)