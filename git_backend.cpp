#include "git_backend.h"
#include <iostream>
#include <algorithm> // For std::min

// Option 1: C++17 Filesystem (ensure CMAKE_CXX_STANDARD 17 is in CMakeLists.txt)
#include <filesystem>
// Option 2: Qt's QDir (if filesystem causes issues or you prefer Qt)
// #include <QDir>
// #include <QString> // if using QDir

GitBackend::GitBackend() {
    git_libgit2_init();
}

GitBackend::~GitBackend() {
    freeCurrentRepo();
    git_libgit2_shutdown();
}

void GitBackend::freeCurrentRepo() {
    if (m_currentRepo) {
        git_repository_free(m_currentRepo);
        m_currentRepo = nullptr;
        m_currentRepoPath.clear();
    }
}

bool GitBackend::initializeRepository(const std::string& path, std::string& error_message) {
    freeCurrentRepo();

    git_repository *repo = nullptr;
    int error = git_repository_init(&repo, path.c_str(), 0);

    if (error < 0) {
        const git_error *e = git_error_last();
        error_message = "Error initializing repository: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if (repo) git_repository_free(repo);
        return false;
    }

    m_currentRepo = repo;
    m_currentRepoPath = path;
    error_message = "Repository initialized and opened at: " + path;
    return true;
}

bool GitBackend::openRepository(const std::string& path, std::string& error_message) {
    if (!std::filesystem::is_directory(path)) {
    // QDir dir_check(QString::fromStdString(path));
    // if (!dir_check.exists()) {
        error_message = "Error: Path is not a valid directory or does not exist: " + path;
        return false;
    }
    freeCurrentRepo();
    int error = git_repository_open(&m_currentRepo, path.c_str());

    if (error < 0) {
        const git_error *e = git_error_last();
        error_message = "Error opening repository: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return false;
    }
    m_currentRepoPath = path;
    error_message = "Repository opened successfully: " + path;
    return true;
}

void GitBackend::closeRepository() {
    freeCurrentRepo();
}

bool GitBackend::isRepositoryOpen() const {
    return m_currentRepo != nullptr;
}

std::string GitBackend::getCurrentRepositoryPath() const {
    return m_currentRepoPath;
}

std::vector<CommitInfo> GitBackend::getCommitLog(int limit, std::string& error_message) {
    std::vector<CommitInfo> log;
    error_message.clear();

    if (!isRepositoryOpen()) {
        error_message = "No repository open to get log from.";
        return log;
    }

    git_revwalk *walker = nullptr;
    int error = git_revwalk_new(&walker, m_currentRepo);
    if (error < 0) {
        const git_error *e = git_error_last();
        error_message = "Error creating revwalker: ";
        error_message += (e && e->message) ? e->message : "Unknown git error";
        if(walker) git_revwalk_free(walker);
        return log;
    }

    // Sort by topological order and time
    git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    // Start from HEAD
    error = git_revwalk_push_head(walker);
    if (error < 0) {
        const git_error *e = git_error_last();
        error_message = "Error pushing HEAD to revwalker: ";
        error_message += (e && e->message) ? e->message : "No commits yet?";
        git_revwalk_free(walker);
        return log;
    }

    git_oid oid;
    git_commit *commit = nullptr;
    int count = 0;

    while (git_revwalk_next(&oid, walker) == 0 && (limit <= 0 || count < limit)) {
        error = git_commit_lookup(&commit, m_currentRepo, &oid);
        if (error < 0) {
            // Could log this error but continue if possible
            error_message = "Error looking up commit."; // Simplified
            git_commit_free(commit); // commit is NULL if lookup fails, but good practice
            continue;
        }

        CommitInfo info;
        char short_oid_str[10] = {0}; // For 7 char OID + null
        git_oid_tostr(short_oid_str, sizeof(short_oid_str)-1, &oid);
        info.oid_short = short_oid_str;

        const git_signature *author = git_commit_author(commit);
        if (author) {
            info.author_name = author->name ? author->name : "N/A";
            info.author_email = author->email ? author->email : "N/A";
        }
        info.commit_time = git_commit_time(commit);
        info.summary = git_commit_summary(commit) ? git_commit_summary(commit) : "[no summary]";

        log.push_back(info);
        git_commit_free(commit);
        commit = nullptr; // Good practice after free
        count++;
    }
    // Check for errors after loop (e.g. if git_revwalk_next failed not due to end)
    if (error < 0 && error != GIT_ITEROVER) {
         const git_error *e = git_error_last();
         error_message = "Error walking revisions: ";
         error_message += (e && e->message) ? e->message : "Unknown git error";
    }


    git_revwalk_free(walker);
    return log;
}