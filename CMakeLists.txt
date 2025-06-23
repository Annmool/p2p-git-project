cmake_minimum_required(VERSION 3.16)
project(P2PGitProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
find_package(Qt5 REQUIRED COMPONENTS Widgets Network)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2)
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Define Your Executable Target ---
add_executable(${PROJECT_NAME}
main.cpp
    
# Core Backend
git_backend.cpp
identity_manager.cpp
repository_manager.cpp
network_manager.cpp

# Main Window and UI Panels
mainwindow.cpp
network_panel.cpp
repo_management_panel.cpp
project_window.cpp
)

# --- Include Directories ---
include_directories(${GIT2_INCLUDE_DIRS})
include_directories(${SODIUM_INCLUDE_DIRS})

# --- Link Libraries to the Defined Target ---
target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Widgets
    Qt5::Network
    ${GIT2_LIBRARIES}
    ${SODIUM_LIBRARIES}
)