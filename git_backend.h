#ifndef GIT_BACKEND_H
#define GIT_BACKEND_H

#include <string>
#include <vector>
#include <git2.h>

struct CommitInfo
{
    std::string sha;
    std::string author_name;
    std::string author_email;
    std::string date;
    std::string summary;
};

struct FileStatus
{
    std::string path;
    unsigned int git_status;
};

class GitBackend
{
public:
    enum class BranchType
    {
        LOCAL = GIT_BRANCH_LOCAL,
        REMOTE = GIT_BRANCH_REMOTE,
        ALL = GIT_BRANCH_ALL
    };

    GitBackend();
    ~GitBackend();

    bool initializeRepository(const std::string &path, std::string &error_message);
    bool openRepository(const std::string &path, std::string &error_message);
    void closeRepository();
    bool isRepositoryOpen() const;
    std::string getCurrentRepositoryPath() const;

    std::vector<CommitInfo> getCommitLog(int max_commits, std::string &error_message, const std::string &specific_ref_name_or_sha = "");
    std::vector<std::string> listBranches(BranchType type, std::string &error_message);
    bool checkoutBranch(const std::string &branch_name, std::string &error_message);
    std::string getCurrentBranch(std::string &error_message);

    // P2P and file operations
    bool createBundle(const std::string &outputDir, const std::string &bundleNameSuggestion, std::string &outBundleFilePath, std::string &error_message);
    bool fetchFromBundle(const std::string &bundlePath, std::string &error_message);
    bool createDiffArchive(const std::string &output_zip_path, const std::string &local_branch, const std::string &remote_branch_base, std::string &error_message);
    // Overload: only include diffs for the given relative paths
    bool createDiffArchive(const std::string &output_zip_path, const std::string &local_branch, const std::string &remote_branch_base, const std::vector<std::string> &include_paths, std::string &error_message);
    bool applyBundle(const std::string &bundle_path, std::string &error_message);

    // Staging and Committing
    std::vector<FileStatus> getRepositoryStatus(std::string &error_message);
    bool stagePath(const std::string &path, std::string &error_message);
    bool unstagePath(const std::string &path, std::string &error_message);
    bool stageAll(std::string &error_message);
    bool unstageAll(std::string &error_message);
    bool commitChanges(const std::string &message, const std::string &author_name, const std::string &author_email, std::string &error_message);

private:
    git_repository *m_currentRepo = nullptr;
    std::string m_currentRepoPath;

    void freeCurrentRepo();
};

#endif // GIT_BACKEND_H