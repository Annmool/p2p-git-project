cmake_minimum_required(VERSION 3.16)
project(P2PGitProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17) # For std::filesystem, ensure your compiler supports it
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
find_package(Qt5 REQUIRED COMPONENTS Widgets)

# --- Use PkgConfig to find LibGit2 ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2)

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

# If using std::filesystem and linking fails (e.g. on older GCC/Clang or some setups):
# You might need to explicitly link against the filesystem library.
# For GCC/Clang, it's often stdc++fs. For MSVC, it's usually automatic with C++17.
# Example for GCC/Clang if needed:
# target_link_libraries(${PROJECT_NAME} PRIVATE Qt5::Widgets ${GIT2_LIBRARIES} stdc++fs)