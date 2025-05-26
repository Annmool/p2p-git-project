#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <vector>
#include <git2.h> // Main libgit2 header

// Structure to hold commit information for the UI
struct CommitInfo {
    std::string oid_short; // Short OID string
    std::string author_name;
    std::string author_email;
    long long commit_time; // Unix timestamp
    std::string summary;   // First line of commit message
};

class GitBackend {
public:
    GitBackend();
    ~GitBackend();

    // Initializes a new Git repository at the given path
    bool initializeRepository(const std::string& path, std::string& error_message);

    // Opens an existing Git repository at the given path
    bool openRepository(const std::string& path, std::string& error_message);

    // Closes the currently open repository, if any
    void closeRepository();

    // Helper to check if a repository is currently open
    bool isRepositoryOpen() const;

    // Helper to get the path of the currently open repository
    std::string getCurrentRepositoryPath() const;

    // Gets the commit log for the current branch of the open repository
    // Returns a vector of CommitInfo. Vector is empty on error or if no commits.
    // Sets error_message on failure.
    std::vector<CommitInfo> getCommitLog(int limit, std::string& error_message);


private:
    git_repository* m_currentRepo = nullptr; // Handle to the currently open repository
    std::string m_currentRepoPath;           // Path of the currently open repository

    // Private helper to free the repository if it's open
    void freeCurrentRepo();
};

#endif // GIT_BACKEND_H