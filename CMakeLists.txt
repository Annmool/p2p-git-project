cmake_minimum_required(VERSION 3.16)
project(P2PGitProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
find_package(Qt5 REQUIRED COMPONENTS Widgets)

# --- Use PkgConfig to find LibGit2 ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2) # This uses libgit2.pc

# --- Define Your Executable Target ---
add_executable(${PROJECT_NAME}
    main.cpp
    mainwindow.cpp
    git_backend.cpp
)

# --- Include Directories (especially for LibGit2) ---
include_directories(${GIT2_INCLUDE_DIRS})

# --- Link Libraries to the Defined Target ---
target_link_libraries(${PROJECT_NAME} PRIVATE Qt5::Widgets ${GIT2_LIBRARIES})