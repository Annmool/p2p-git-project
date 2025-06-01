#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <vector>
#include <git2.h>

// Define CommitInfo struct
struct CommitInfo {
    std::string sha;
    std::string author_name;
    std::string author_email;
    std::string date; // Formatted date string
    std::string summary;
};

class GitBackend {
public:
    // Enum to specify which types of branches to list
    enum class BranchType {
        LOCAL = GIT_BRANCH_LOCAL,
        REMOTE = GIT_BRANCH_REMOTE,
        ALL = GIT_BRANCH_ALL
    };

    GitBackend();
    ~GitBackend();

    bool initializeRepository(const std::string& path, std::string& error_message);
    bool openRepository(const std::string& path, std::string& error_message);
    void closeRepository();
    bool isRepositoryOpen() const;
    std::string getCurrentRepositoryPath() const;

    std::vector<CommitInfo> getCommitLog(int max_commits, std::string& error_message, const std::string& specific_ref_name_or_sha = "");
    std::vector<std::string> listBranches(BranchType type, std::string& error_message);
    bool checkoutBranch(const std::string& branch_name, std::string& error_message);
    std::string getCurrentBranch(std::string& error_message);

private:
    git_repository* m_currentRepo = nullptr;
    std::string m_currentRepoPath;

    void freeCurrentRepo();
};

#endif // GIT_BACKEND_H