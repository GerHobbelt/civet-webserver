cmake_minimum_required(VERSION 3.13...3.16)
project(mongoose)

list(APPEND DEFS "-DMG_ENABLE_HTTP_STREAMING_MULTIPART")
list(APPEND DEFS "-DMG_ENABLE_WEBSOCKET")
list(APPEND DEFS "-DMG_ENABLE_CALLBACK_USERDATA")
add_definitions(${DEFS})
add_library(mongoose SHARED mongoose.c mongoose.h)
target_include_directories(mongoose PUBLIC ./)
install(TARGETS mongoose
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include)
