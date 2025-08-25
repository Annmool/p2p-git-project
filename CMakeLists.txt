cmake_minimum_required(VERSION 3.16)
project(SyncIt VERSION 0.1 LANGUAGES CXX) # Changed project name for a more professional feel

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
find_package(Qt5 REQUIRED COMPONENTS Widgets Network Svg) # <<< ADD Svg HERE

find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2)
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Define Your Executable Target ---
add_executable(${PROJECT_NAME}
    main.cpp
    git_backend.cpp
    identity_manager.cpp
    repository_manager.cpp
    network_manager.cpp
    mainwindow.cpp
    dashboard_panel.cpp
    network_panel.cpp
    project_window.cpp
    notifications_panel.cpp
    custom_dialogs.cpp
    welcome_window.cpp
    info_dot.cpp
    res/res.qrc
)

# --- Include Directories ---
include_directories(${GIT2_INCLUDE_DIRS})
include_directories(${SODIUM_INCLUDE_DIRS})

# --- Link Libraries to the Defined Target ---
target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Widgets
    Qt5::Network
    Qt5::Svg # <<< ADD Svg HERE
    ${GIT2_LIBRARIES}
    ${SODIUM_LIBRARIES}
)