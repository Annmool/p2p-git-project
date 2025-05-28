#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <vector>  // For returning list of branches and commit log
#include <git2.h>  // Main libgit2 header

// Define CommitInfo struct within the header or in a common types header if it grows
struct CommitInfo {
    std::string sha;
    std::string author_name;
    std::string author_email;
    std::string date; // Formatted date string
    std::string summary;
    // long long commit_time; // If you prefer raw timestamp
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

    // Fetches commit log
    std::vector<CommitInfo> getCommitLog(int max_commits, std::string& error_message);

    // Lists branch names (local branches by default)
    std::vector<std::string> listBranches(std::string& error_message);

    // Checks out the specified branch
    bool checkoutBranch(const std::string& branch_name, std::string& error_message);

    // Gets the name of the current branch
    std::string getCurrentBranch(std::string& error_message);

private:
    git_repository* m_currentRepo = nullptr; // Handle to the currently open repository
    std::string m_currentRepoPath;           // Path of the currently open repository

    // Private helper to free the repository if it's open
    void freeCurrentRepo();
};

#endif // GIT_BACKEND_H