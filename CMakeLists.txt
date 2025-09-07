cmake_minimum_required(VERSION 3.16)

# Project name and language
project(detection_suspecious_messages_in_whatsapp VERSION 0.1 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Collect all source files automatically
file(GLOB_RECURSE SOURCES "${CMAKE_SOURCE_DIR}/src/*.cpp")

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Optional: set MSVC specific flags
if(MSVC)
    # Enable warnings as errors
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
endif()
