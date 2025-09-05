cmake_minimum_required(VERSION 3.16)

project(detection_suspecious_messages_in_whatsapp VERSION 0.1 LANGUAGES CXX)

# Enable automatic Qt features
set(CMAKE_AUTOUIC ON)   # auto-generate ui_*.h
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/forms)
set(CMAKE_AUTOMOC ON)   # auto-generate moc_*.cpp
set(CMAKE_AUTORCC ON)   # auto-generate qrc_*.cpp
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# Collect sources, headers, and forms recursively
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h")
file(GLOB_RECURSE FORMS "forms/*.ui")

# Combine all into project sources
set(PROJECT_SOURCES
    ${SOURCES}
    ${HEADERS}
    ${FORMS}
)

# Create executable
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(detection_suspecious_messages_in_whatsapp
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(detection_suspecious_messages_in_whatsapp SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(detection_suspecious_messages_in_whatsapp
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Link Qt Widgets
target_link_libraries(detection_suspecious_messages_in_whatsapp PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# Include directories (use target_include_directories for proper scope)
target_include_directories(detection_suspecious_messages_in_whatsapp
    PRIVATE
        include
)

# macOS bundle properties
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.detection_suspecious_messages_in_whatsapp)
endif()

set_target_properties(detection_suspecious_messages_in_whatsapp PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Install rules
include(GNUInstallDirs)
install(TARGETS detection_suspecious_messages_in_whatsapp
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Finalize for Qt6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(detection_suspecious_messages_in_whatsapp)
endif()
