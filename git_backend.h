// git_backend.h
#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <vector>
#include <git2.h> // Include libgit2 header

// Define CommitInfo struct
struct CommitInfo
{
    std::string sha;
    std::string author_name;
    std::string author_email;
    std::string date; // Formatted date string (e.g., "YYYY-MM-DD HH:MM:SS Zone")
    std::string summary;
};

class GitBackend
{
public:
    // Enum to specify which types of branches to list
    enum class BranchType
    {
        LOCAL = GIT_BRANCH_LOCAL,
        REMOTE = GIT_BRANCH_REMOTE,
        ALL = GIT_BRANCH_LOCAL | GIT_BRANCH_REMOTE // Combine flags for ALL
    };

    GitBackend();
    ~GitBackend();

    // Repository Management
    bool initializeRepository(const std::string &path, std::string &error_message);
    bool openRepository(const std::string &path, std::string &error_message);
    void closeRepository();
    bool isRepositoryOpen() const;
    std::string getCurrentRepositoryPath() const;

    // Repository Operations
    // Get commit log for a specific ref (branch, tag, SHA) or HEAD (if ref is empty)
    std::vector<CommitInfo> getCommitLog(int max_commits, std::string &error_message, const std::string &specific_ref_name_or_sha = "");
    std::vector<std::string> listBranches(BranchType type, std::string &error_message); // List local, remote, or all branches/tags
    bool checkoutBranch(const std::string &branch_name, std::string &error_message);    // Checkout a branch or ref

    // Bundle Operations (using system git command)
    // Creates a bundle file from the current repository
    bool createBundle(const std::string &outputDir, const std::string &bundleNameSuggestion, std::string &outBundleFilePath, std::string &error_message);
    // Note: applyBundle (clone from bundle) is typically done externally via QProcess/git command.

    // Status
    std::string getCurrentBranch(std::string &error_message); // Get the current branch name or detached HEAD state

private:
    git_repository *m_currentRepo = nullptr; // Pointer to the currently open libgit2 repository object
    std::string m_currentRepoPath;           // Path to the root of the currently open repository

    void freeCurrentRepo(); // Helper to free the current repository object
};

#endif // GIT_BACKEND_H