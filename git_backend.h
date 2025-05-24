#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <git2.h> // Main libgit2 header

class GitBackend {
public:
    GitBackend();
    ~GitBackend();

    // Initializes a new Git repository at the given path
    // Returns true on success, false on failure
    // Sets error_message if an error occurs
    bool initializeRepository(const std::string& path, std::string& error_message);

private:
    // You might add private members here if needed for more complex operations
};

#endif // GIT_BACKEND_H