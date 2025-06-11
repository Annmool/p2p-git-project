cmake_minimum_required(VERSION 3.16)
project(P2PGitProject VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# --- Find Packages ---
find_package(Qt5 REQUIRED COMPONENTS Widgets Network) 
# find_package(Qt5 REQUIRED COMPONENTS Network) # This line is commented out, which is fine if the combined one works

find_package(PkgConfig REQUIRED)
pkg_check_modules(GIT2 REQUIRED libgit2)
pkg_check_modules(SODIUM REQUIRED libsodium) # For libsodium

# --- Define Your Executable Target ---
add_executable(${PROJECT_NAME}
    main.cpp
    mainwindow.cpp
    git_backend.cpp
    network_manager.cpp
    identity_manager.cpp 
) # <--- CORRECTED TO A CLOSING PARENTHESIS

# --- Include Directories ---
include_directories(${GIT2_INCLUDE_DIRS})
include_directories(${SODIUM_INCLUDE_DIRS}) # Add libsodium includes
# Qt5 include directories are usually handled by linking targets

# --- Link Libraries to the Defined Target ---
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Qt5::Widgets 
    Qt5::Network
    ${GIT2_LIBRARIES}
    ${SODIUM_LIBRARIES} # Link libsodium
)

# Optional: Link stdc++fs if std::filesystem causes issues on your compiler
# if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_CLANG)
#   if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0") # Example for older GCC
#     target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
#   endif()
# endif()