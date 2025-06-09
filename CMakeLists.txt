cmake_minimum_required(VERSION 3.16)
project(P2PGitProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
# Using the two separate find_package calls that worked for you
find_package(Qt5 REQUIRED COMPONENTS Widgets) 
find_package(Qt5 REQUIRED COMPONENTS Network) 

# --- Use PkgConfig to find LibGit2 ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2)
pkg_check_modules(SODIUM REQUIRED libsodium) 

# --- Define Your Executable Target ---
add_executable(${PROJECT_NAME}
    main.cpp
    mainwindow.cpp
    git_backend.cpp
    network_manager.cpp # Ensure this is added
    identity_manager.cpp
)

# --- Include Directories (especially for LibGit2) ---
include_directories(
    ${GIT2_INCLUDE_DIRS}
    ${SODIUM_LIBRARIES} #
    )
# Qt5 include directories are typically handled by linking Qt5::Widgets and Qt5::Network

# --- Link Libraries to the Defined Target ---
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Qt5::Widgets 
    Qt5::Network
    ${GIT2_LIBRARIES}
    ${SODIUM_LIBRARIES} #
)

# If using std::filesystem and linking fails on your specific GCC setup
# (e.g. "undefined reference to std::filesystem::...")
# you might need to add stdc++fs. Test without it first.
# On GCC 9+ with CMAKE_CXX_STANDARD 17, it's often not needed.
# if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
#   if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0") # Example for GCC < 9
#     target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
#   endif()
# endif()