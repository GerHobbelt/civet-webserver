cmake_minimum_required(VERSION 3.13...3.16)
project(mongoose)

list(APPEND DEFS "-DMG_ENABLE_HTTP_STREAMING_MULTIPART=1")
list(APPEND DEFS "-DMG_ENABLE_HTTP_WEBSOCKET=1")
list(APPEND DEFS "-DMG_ENABLE_THREADS=1")
list(APPEND DEFS "-DMG_ENABLE_CALLBACK_USERDATA")
list(APPEND DEFS "-DMG_ENABLE_HTTP_URL_REWRITES")
add_definitions(${DEFS})
add_library(mongoose SHARED mongoose.c mongoose.h)
target_include_directories(mongoose PUBLIC ./)
set_target_properties(mongoose PROPERTIES PUBLIC_HEADER mongoose.h)
install(TARGETS mongoose
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include)
