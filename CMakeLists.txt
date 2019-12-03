cmake_minimum_required(VERSION 2.8)
project (bot)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_IDR}/bin/)

include_directories(BEFORE src/imtjson/src src/server/src src )
add_compile_options(-std=c++17)
add_compile_options(-Wall -Who-noexcept-type)

add_subdirectory (src/imtjson/src/imtjson EXCLUDE_FROM_ALL)
add_subdirectory (src/server/src/simpleServe EXCLUDE_FROM_ALL)
add_subdirectory (src/bitmex)
add_subdirectory (src/simplefx)
add_subdirectory (src/main)

install(DIRECTORY conf DESTINATION ".")
install(DIRECTORY www DESTINATION ".")
install(DIRECTORY conf DESTINATION "data")
install(DIRECTORY conf DESTINATION "log")


