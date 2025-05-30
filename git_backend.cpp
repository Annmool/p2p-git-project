#include "git_backend.h"
#include <iostream>
#include <ctime> // For strftime in getCommitLog
#include <algorithm> // For std::min if needed, though not strictly used here yet

// Option 1: C++17 Filesystem
#include <filesystem>
// Option 2: Qt's QDir (alternative for path checking)
// #include <QDir>
// #include <QString>


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
    // If using QDir for check:
    // QDir dir_check(QString::fromStdString(path));
    // if (!dir_check.exists() || !QFileInfo(QString::fromStdString(path)).isDir()) {
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

std::vector<CommitInfo> GitBackend::getCommitLog(int max_commits, std::string& error_message) {
    std::vector<CommitInfo> log_entries;
    error_message.clear();

    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return log_entries;
    }

    int is_unborn = git_repository_head_unborn(m_currentRepo);
    if (is_unborn < 0) { // Error checking unborn status itself
        const git_error *e = git_error_last();
        error_message = "Failed to check repository HEAD state: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return log_entries;
    }
    if (is_unborn == 1) { // HEAD is unborn, meaning no commits yet
        // No error message needed here if you want the UI to just show "No commits"
        // Or, you can set a specific informational message:
        // error_message = "Repository is empty. Make your first commit!";
        return log_entries; // Return an empty log, no commits to walk
    }

    git_revwalk *walk = nullptr;
    git_commit *commit = nullptr;
    git_oid oid;

    if (git_revwalk_new(&walk, m_currentRepo) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to create revwalk: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return log_entries;
    }

    git_revwalk_sorting(walk, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL); // Sort by time (newest first usually) and topology

    if (git_revwalk_push_head(walk) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to push HEAD to revwalk: "; // Simpler message now
        error_message += (e && e->message) ? e->message : "Unknown error";
        git_revwalk_free(walk);
        return log_entries;
    }

    int count = 0;
    int error_walk;
    while ((error_walk = git_revwalk_next(&oid, walk)) == 0 && (max_commits <= 0 || count < max_commits)) {
        if (git_commit_lookup(&commit, m_currentRepo, &oid) != 0) {
            const git_error *e = git_error_last();
            error_message = "Failed to lookup commit: ";
            error_message += (e && e->message) ? e->message : "Unknown error";
            // Potentially break or just skip this commit
            if(commit) git_commit_free(commit); // Should be null but defensive
            commit = nullptr;
            continue;
        }

        CommitInfo info;
        char sha_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(sha_str, sizeof(sha_str), git_commit_id(commit));
        info.sha = sha_str;

        const git_signature *author = git_commit_author(commit);
        if (author) {
            info.author_name = author->name ? author->name : "N/A";
            info.author_email = author->email ? author->email : "N/A";
            
            // Format date
            char time_buf[64];
            time_t t = (time_t)author->when.time;
            // Using gmtime for UTC, localtime for local timezone
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%S", localtime(&t)); // ISO-like
            info.date = time_buf;
        } else {
            info.author_name = "N/A";
            info.author_email = "N/A";
            info.date = "N/A";
        }

        info.summary = git_commit_summary(commit) ? git_commit_summary(commit) : "[no summary]";
        log_entries.push_back(info);

        git_commit_free(commit);
        commit = nullptr;
        count++;
    }
     if (error_walk < 0 && error_walk != GIT_ITEROVER) { // GIT_ITEROVER means end of iteration
        const git_error *e = git_error_last();
        error_message = "Error during revwalk: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
    }


    if (commit) git_commit_free(commit);
    git_revwalk_free(walk);

    if (log_entries.empty() && count == 0 && error_message.empty()) {
        error_message = "No commits found in current branch/HEAD.";
    }

    return log_entries;
}

std::vector<std::string> GitBackend::listBranches(BranchType type, std::string& error_message) {
    std::vector<std::string> branches;
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return branches;
    }

    git_branch_iterator *it = nullptr;
    // Use the passed 'type' to determine which branches to iterate over
    if (git_branch_iterator_new(&it, m_currentRepo, static_cast<git_branch_t>(type)) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to create branch iterator: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return branches;
    }

    git_reference *ref = nullptr;
    git_branch_t iterated_branch_type; // To store the type of branch found
    const char *branch_name_utf8 = nullptr;

    int error;
    while ((error = git_branch_next(&ref, &iterated_branch_type, it)) == 0) {
        if (git_branch_name(&branch_name_utf8, ref) == 0) {
            branches.push_back(branch_name_utf8);
        } else {
        }
        git_reference_free(ref);
        ref = nullptr;
    }
    if (error < 0 && error != GIT_ITEROVER) {
        const git_error *e = git_error_last();
        error_message = "Error iterating branches: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
    }

    if(ref) git_reference_free(ref);
    git_branch_iterator_free(it);

    return branches;
}

bool GitBackend::checkoutBranch(const std::string& branch_name, std::string& error_message) {
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return false;
    }

    std::string full_ref_name = "refs/heads/" + branch_name;

    // Optional: Check if branch exists first (git_revparse_single or git_branch_lookup)
    // git_object *target_object = nullptr;
    // if (git_revparse_single(&target_object, m_currentRepo, full_ref_name.c_str()) != 0) { ... error ... }
    // if(target_object) git_object_free(target_object);

    if (git_repository_set_head(m_currentRepo, full_ref_name.c_str()) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to set HEAD to branch '" + branch_name + "': ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return false;
    }

    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    if (git_checkout_head(m_currentRepo, &opts) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to checkout working directory for branch '" + branch_name + "': ";
        error_message += (e && e->message) ? e->message : "Changes might prevent checkout.";
        // Consider attempting to revert HEAD if checkout fails, though this adds complexity.
        return false;
    }

    error_message = "Successfully checked out branch: " + branch_name;
    return true;
}

std::string GitBackend::getCurrentBranch(std::string& error_message) {
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return "";
    }

    git_reference *head_ref = nullptr;
    int err = git_repository_head(&head_ref, m_currentRepo);

    if (err == GIT_EUNBORNBRANCH || err == GIT_ENOTFOUND) {
        // error_message = "HEAD is unborn or not found."; // Informational, not necessarily an error for display
        if(head_ref) git_reference_free(head_ref);
        return "[Detached HEAD / Unborn]";
    } else if (err != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to get HEAD reference: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if(head_ref) git_reference_free(head_ref);
        return ""; // Indicates an error occurred
    }

    // Check if HEAD is a symbolic reference to a branch
    if (git_reference_is_branch(head_ref) || git_reference_is_remote(head_ref)) { // is_remote for remote tracking branches if needed
        const char* branch_name_utf8 = git_reference_shorthand(head_ref);
        if (branch_name_utf8) {
            std::string current_branch = branch_name_utf8;
            git_reference_free(head_ref);
            return current_branch;
        } else {
            error_message = "Failed to get shorthand name for current branch reference.";
        }
    } else { // Detached HEAD (points directly to a commit)
        // error_message = "HEAD is detached."; // Informational
        git_reference_free(head_ref);
        return "[Detached HEAD]";
    }
    
    // Fallback or if shorthand failed
    if(head_ref) git_reference_free(head_ref);
    return "[Unknown State]";
}