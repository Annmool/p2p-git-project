#include "git_backend.h"
#include <iostream> // For potential std::cerr diagnostics
#include <ctime>    // For strftime
#include <algorithm>// For std::min (if needed elsewhere)
#include <filesystem> // For path checking in openRepository
#include <QProcess> // For running git command line
#include <QTemporaryFile> // For temporary bundle file name
#include <QDir>
#include <QFileInfo>
#include <QDebug> // For qDebug

// GitBackend Constructor and Destructor
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

// initializeRepository, openRepository, closeRepository, isRepositoryOpen, getCurrentRepositoryPath
// These should be the same as your previously working versions.
// For completeness, I'll include the versions from your context.

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

bool GitBackend::createBundle(const std::string& outputDirStr, const std::string& bundleNameSuggestion, std::string& outBundleFilePath, std::string& error_message) {
    if (!isRepositoryOpen()) {
        error_message = "No repository is open to create a bundle from.";
        return false;
    }

    QDir outputDir(QString::fromStdString(outputDirStr));
    if (!outputDir.exists()) {
        if (!outputDir.mkpath(".")) {
            error_message = "Could not create output directory for bundle: " + outputDirStr;
            return false;
        }
    }

    QString safeBundleName = QString::fromStdString(bundleNameSuggestion);
    safeBundleName.remove(QRegExp(QStringLiteral("[^a-zA-Z0-9_.-]")));
    if(safeBundleName.isEmpty()) safeBundleName = "repo";
    if(!safeBundleName.endsWith(".bundle")) safeBundleName += ".bundle";
    
    QString bundleFilePathQ = outputDir.filePath(safeBundleName);
    outBundleFilePath = bundleFilePathQ.toStdString();

    QProcess gitProcess;
    gitProcess.setWorkingDirectory(QString::fromStdString(m_currentRepoPath));
    QStringList arguments;
    arguments << "bundle" << "create" << bundleFilePathQ << "--all";

    qDebug() << "GitBackend: Running git" << arguments.join(" ") << "in" << QString::fromStdString(m_currentRepoPath);

    gitProcess.start("git", arguments);
    if (!gitProcess.waitForStarted(-1)) {
        error_message = "Failed to start git bundle process: " + gitProcess.errorString().toStdString();
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        return false;
    }
    if (!gitProcess.waitForFinished(-1)) {
        error_message = "Git bundle process timed out or did not finish: " + gitProcess.errorString().toStdString();
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        return false;
    }

    if (gitProcess.exitStatus() == QProcess::NormalExit && gitProcess.exitCode() == 0) {
        if (QFile(bundleFilePathQ).exists()) {
            error_message = "Bundle created successfully: " + outBundleFilePath;
            qInfo() << "GitBackend:" << QString::fromStdString(error_message);
            return true;
        } else {
            error_message = "Git bundle process finished but bundle file not found at: " + outBundleFilePath;
            qWarning() << "GitBackend:" << QString::fromStdString(error_message);
            qWarning() << "Git bundle stdout:" << QString(gitProcess.readAllStandardOutput());
            qWarning() << "Git bundle stderr:" << QString(gitProcess.readAllStandardError());
            return false;
        }
    } else {
        error_message = "Git bundle process failed. Exit code: " + std::to_string(gitProcess.exitCode()) +
                        ". Stderr: " + QString(gitProcess.readAllStandardError()).toStdString();
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        std::remove(outBundleFilePath.c_str());
        return false;
    }
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


// Corrected getCommitLog
std::vector<CommitInfo> GitBackend::getCommitLog(int max_commits, std::string& error_message, const std::string& specific_ref_name_or_sha) {
    std::vector<CommitInfo> log_entries;
    error_message.clear();
    int count = 0;

    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return log_entries;
    }

    git_revwalk *walk = nullptr;
    git_commit *commit_obj = nullptr;

    if (git_revwalk_new(&walk, m_currentRepo) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to create revwalk: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return log_entries;
    }
    git_revwalk_sorting(walk, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL);

    bool pushed_successfully = false;
    if (!specific_ref_name_or_sha.empty()) {
        // Try to push it as a reference first (e.g., "refs/heads/main", "origin/main", "HEAD")
        // libgit2 will try to resolve this ref to a commit.
        // Note: "origin/main" is a shorthand, full ref is "refs/remotes/origin/main"
        // git_revwalk_push_ref handles some shorthands. If not, use full names.
        std::string ref_to_push = specific_ref_name_or_sha;
        if (specific_ref_name_or_sha.find('/') != std::string::npos && 
            specific_ref_name_or_sha.rfind("refs/", 0) != 0) { // Shorthand like "origin/main"
             // Convert shorthands like "origin/main" to "refs/remotes/origin/main"
            bool is_likely_remote = true; // Assume, adjust if local branches can have '/' by user convention
            // A better check would be to see if specific_ref_name_or_sha matches a known local branch exactly.
            // For now, simple heuristic:
             std::vector<std::string> local_branches_temp;
             std::string ignored_err;
             local_branches_temp = listBranches(BranchType::LOCAL, ignored_err);
             bool found_as_local = false;
             for(const auto& lb : local_branches_temp){
                 if(lb == specific_ref_name_or_sha){
                     found_as_local = true;
                     break;
                 }
             }
            if(found_as_local){
                 ref_to_push = "refs/heads/" + specific_ref_name_or_sha;
            } else { // Assume remote or some other qualified name
                 ref_to_push = "refs/remotes/" + specific_ref_name_or_sha;
            }
        } else if (specific_ref_name_or_sha.find('/') == std::string::npos && specific_ref_name_or_sha != "HEAD"){
            // Likely a local branch name like "main"
            ref_to_push = "refs/heads/" + specific_ref_name_or_sha;
        }
        // Else, it might be "HEAD", a full ref name, or a SHA

        int push_ref_err = git_revwalk_push_ref(walk, ref_to_push.c_str());
        if (push_ref_err == 0) {
            pushed_successfully = true;
        } else {
            // If pushing as a ref failed, it might be a raw SHA string. Try to parse and push OID.
            git_oid oid_to_push;
            if (git_oid_fromstr(&oid_to_push, specific_ref_name_or_sha.c_str()) == 0) { // Check if it's a SHA
                if (git_revwalk_push(walk, &oid_to_push) == 0) {
                    pushed_successfully = true;
                } else { // Valid SHA but couldn't push (e.g. commit not in repo, or revwalk issue)
                    const git_error *e = git_error_last();
                    error_message = "Failed to push specific OID '" + specific_ref_name_or_sha + "' to revwalk: ";
                    error_message += (e && e->message) ? e->message : "Unknown error";
                }
            } else { // Failed as a ref and failed as an OID string
                const git_error *e_ref = git_error_last(); // Error from git_revwalk_push_ref
                error_message = "Failed to push reference '" + ref_to_push + "' (derived from '" + specific_ref_name_or_sha +"') to revwalk, and not a valid SHA: ";
                error_message += (e_ref && e_ref->message) ? e_ref->message : "Unknown error";
            }
        }
    } else { // specific_ref_name_or_sha is empty, use HEAD
        if (git_repository_head_unborn(m_currentRepo) == 1) {
            git_revwalk_free(walk);
            // error_message = "Repository is empty or HEAD is unborn."; // UI can show "no commits"
            return log_entries; // Correct: no commits, no error needed from backend here
        }
        if (git_revwalk_push_head(walk) == 0) {
            pushed_successfully = true;
        } else {
            const git_error *e = git_error_last();
            error_message = "Failed to push HEAD to revwalk: ";
            error_message += (e && e->message) ? e->message : "Unknown error";
        }
    }

    if (!pushed_successfully) {
        // error_message should have been set by the failing push attempt.
        // If not (which would be a logic flaw above), set a generic one.
        if (error_message.empty()) {
             error_message = "Could not start commit traversal for the specified reference. Push to revwalk failed.";
        }
        if (walk) git_revwalk_free(walk);
        return log_entries;
    }
    
    git_oid loop_oid;
    int error_walk;
    while ((error_walk = git_revwalk_next(&loop_oid, walk)) == 0 && (max_commits <= 0 || count < max_commits)) {
        if (git_commit_lookup(&commit_obj, m_currentRepo, &loop_oid) != 0) {
            const git_error *e = git_error_last();
            std::string commit_load_err_msg = "Warning: Failed to lookup commit ";
            commit_load_err_msg += git_oid_tostr_s(&loop_oid);
            commit_load_err_msg += ": ";
            commit_load_err_msg += (e && e->message) ? e->message : "Unknown error";
            std::cerr << commit_load_err_msg << std::endl; // Log to console for debugging
            if (error_message.empty()) error_message = commit_load_err_msg; // Set as main error if first one
            else error_message += " | " + commit_load_err_msg;

            if (commit_obj) git_commit_free(commit_obj);
            commit_obj = nullptr;
            continue; // Try to get next commit
        }

        CommitInfo info;
        char sha_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(sha_str, sizeof(sha_str), git_commit_id(commit_obj));
        info.sha = sha_str;

        const git_signature *author = git_commit_author(commit_obj);
        if (author) {
            info.author_name = (author->name != nullptr) ? author->name : "N/A";
            info.author_email = (author->email != nullptr) ? author->email : "N/A";
            char time_buf[64];
            time_t t = (time_t)author->when.time;
            if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t)) > 0) {
                info.date = time_buf;
            } else {
                info.date = "Invalid date";
            }
        } else {
            info.author_name = "N/A";
            info.author_email = "N/A";
            info.date = "N/A";
        }

        const char *summary_cstr = git_commit_summary(commit_obj);
        info.summary = (summary_cstr != nullptr) ? summary_cstr : "[no summary]";
        
        log_entries.push_back(info);

        git_commit_free(commit_obj);
        commit_obj = nullptr;
        count++;
    }
    
    if (error_walk < 0 && error_walk != GIT_ITEROVER) { 
        const git_error *e = git_error_last();
        std::string revwalk_err_str = "Error during revwalk: ";
        revwalk_err_str += (e && e->message) ? e->message : "Unknown error";
        if (error_message.empty()) error_message = revwalk_err_str;
        else error_message = revwalk_err_str + " | " + error_message;
    }

    if (commit_obj) git_commit_free(commit_obj); // Should be null
    git_revwalk_free(walk);

    if (log_entries.empty() && count == 0 && error_message.empty()) {
        // This means pushed_successfully was true, loop finished (or didn't start if no commits),
        // and no errors were reported during the loop.
        error_message = "No commits found for ";
        if (specific_ref_name_or_sha.empty()) {
            error_message += "current HEAD.";
        } else {
            error_message += "'" + specific_ref_name_or_sha + "'.";
        }
    }
    return log_entries;
}

// listBranches - same as your working version
std::vector<std::string> GitBackend::listBranches(BranchType type, std::string& error_message) {
    std::vector<std::string> branches;
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return branches;
    }
    git_branch_iterator *it = nullptr;
    if (git_branch_iterator_new(&it, m_currentRepo, static_cast<git_branch_t>(type)) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to create branch iterator: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return branches;
    }
    git_reference *ref = nullptr;
    git_branch_t iterated_branch_type;
    const char *branch_name_utf8 = nullptr;
    int error;
    while ((error = git_branch_next(&ref, &iterated_branch_type, it)) == 0) {
        if (git_branch_name(&branch_name_utf8, ref) == 0) {
            branches.push_back(branch_name_utf8);
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

// checkoutBranch - Using the "Option 2 style" (create local tracking branch)
bool GitBackend::checkoutBranch(const std::string& branch_name_from_ui, std::string& error_message) {
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return false;
    }

    // Determine if the intent is to checkout a remote-tracking branch
    // This heuristic can be improved by checking if branch_name_from_ui exists in remote branches list
    bool is_remote_checkout_intent = false;
    std::string ignored_err;
    std::vector<std::string> remote_branch_list = listBranches(BranchType::REMOTE, ignored_err);
    for(const auto& rb_name : remote_branch_list) {
        if (rb_name == branch_name_from_ui) {
            is_remote_checkout_intent = true;
            break;
        }
    }


    if (is_remote_checkout_intent) {
        size_t last_slash = branch_name_from_ui.rfind('/');
        std::string desired_local_branch_name = (last_slash == std::string::npos) ? branch_name_from_ui : branch_name_from_ui.substr(last_slash + 1);
        
        if (desired_local_branch_name == "HEAD") { // Avoid creating local "HEAD"
             git_reference* head_symref = nullptr;
             std::string remote_head_ref_name = "refs/remotes/" + branch_name_from_ui; // e.g. refs/remotes/origin/HEAD
             if (git_reference_lookup(&head_symref, m_currentRepo, remote_head_ref_name.c_str()) == 0) {
                if (git_reference_type(head_symref) == GIT_REFERENCE_SYMBOLIC) {
                    const char* target_ref_name = git_reference_symbolic_target(head_symref); // e.g. refs/remotes/origin/main
                    if (target_ref_name) {
                        std::string resolved_target_str = target_ref_name;
                        last_slash = resolved_target_str.rfind('/'); // from refs/remotes/origin/main -> main
                        desired_local_branch_name = (last_slash == std::string::npos) ? resolved_target_str : resolved_target_str.substr(last_slash + 1);
                    }
                }
                git_reference_free(head_symref);
             }
             if (desired_local_branch_name == "HEAD") { // If still HEAD after trying to resolve
                 error_message = "Cannot derive a valid local branch name from '" + branch_name_from_ui + "'. Please select a specific remote branch (e.g., origin/main).";
                 return false;
             }
        }

        std::string local_branch_ref_name_full = "refs/heads/" + desired_local_branch_name;
        std::string remote_tracking_ref_shorthand = branch_name_from_ui;

        git_reference *local_branch_ref = nullptr;
        int err = git_branch_lookup(&local_branch_ref, m_currentRepo, desired_local_branch_name.c_str(), GIT_BRANCH_LOCAL);

        if (err == 0) { // Local branch already exists, just check it out
            git_reference_free(local_branch_ref);
            if (git_repository_set_head(m_currentRepo, local_branch_ref_name_full.c_str()) != 0) {
                const git_error *e = git_error_last();
                error_message = "Failed to set HEAD to existing local branch '" + desired_local_branch_name + "': ";
                error_message += (e && e->message) ? e->message : "Unknown error";
                return false;
            }
            error_message = "Switched to existing local branch: " + desired_local_branch_name;
        } else if (err == GIT_ENOTFOUND) { // Local branch does not exist, create it
            git_commit *target_commit = nullptr;
            std::string full_remote_ref_to_resolve = "refs/remotes/" + remote_tracking_ref_shorthand;
            
            int revparse_err = git_revparse_single(reinterpret_cast<git_object**>(&target_commit), m_currentRepo, full_remote_ref_to_resolve.c_str());
            
            if (revparse_err != 0 || !target_commit || git_object_type(reinterpret_cast<git_object*>(target_commit)) != GIT_OBJECT_COMMIT) {
                const git_error *e = git_error_last();
                error_message = "Remote branch '" + remote_tracking_ref_shorthand + "' could not be resolved to a commit: ";
                error_message += (e && e->message) ? e->message : "Unknown error or not a commit object";
                if (target_commit) git_object_free(reinterpret_cast<git_object*>(target_commit));
                return false;
            }

            git_reference *newly_created_local_branch_ref = nullptr;
            err = git_branch_create(&newly_created_local_branch_ref, m_currentRepo, desired_local_branch_name.c_str(), target_commit, 0 /*force=false*/);
            git_commit_free(target_commit);
            if (err != 0) {
                const git_error *e = git_error_last();
                error_message = "Failed to create local branch '" + desired_local_branch_name + "': ";
                error_message += (e && e->message) ? e->message : "Unknown error";
                return false;
            }

            err = git_branch_set_upstream(newly_created_local_branch_ref, remote_tracking_ref_shorthand.c_str());
            if (err != 0) { /* Log warning, but proceed */ }

            if (git_repository_set_head(m_currentRepo, git_reference_name(newly_created_local_branch_ref)) != 0) {
                const git_error *e = git_error_last();
                error_message = "Failed to set HEAD to newly created branch '" + desired_local_branch_name + "': ";
                error_message += (e && e->message) ? e->message : "Unknown error";
                git_reference_free(newly_created_local_branch_ref);
                return false;
            }
            git_reference_free(newly_created_local_branch_ref);
            error_message = "Created and checked out local branch '" + desired_local_branch_name + "' tracking '" + remote_tracking_ref_shorthand + "'";
        } else { // Some other error looking up local branch
            const git_error *e = git_error_last();
            error_message = "Error looking up local branch '" + desired_local_branch_name + "': ";
            error_message += (e && e->message) ? e->message : "Unknown error";
            return false;
        }
    } else { // Standard local branch checkout
        std::string local_branch_full_ref = "refs/heads/" + branch_name_from_ui;
        if (git_repository_set_head(m_currentRepo, local_branch_full_ref.c_str()) != 0) {
            const git_error *e = git_error_last();
            error_message = "Failed to set HEAD to local branch '" + branch_name_from_ui + "': ";
            error_message += (e && e->message) ? e->message : "Reference not found or not a branch.";
            return false;
        }
        error_message = "Successfully checked out local branch: " + branch_name_from_ui;
    }

    // Common part: Update working directory
    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    opts.checkout_strategy = GIT_CHECKOUT_SAFE; // Or GIT_CHECKOUT_FORCE if needed
    if (git_checkout_head(m_currentRepo, &opts) != 0) {
        const git_error *e = git_error_last();
        std::string previous_message = error_message; // Preserve the success/failure message from setting HEAD
        error_message = previous_message + ". Then, failed to update working directory: ";
        error_message += (e && e->message) ? e->message : "Changes might prevent checkout.";
        return false;
    }
    return true;
}


// getCurrentBranch - same as your working version
std::string GitBackend::getCurrentBranch(std::string& error_message) {
    error_message.clear();
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return "";
    }
    git_reference *head_ref = nullptr;
    int err = git_repository_head(&head_ref, m_currentRepo);
    if (err == GIT_EUNBORNBRANCH || err == GIT_ENOTFOUND) {
        if(head_ref) git_reference_free(head_ref);
        return "[Detached HEAD / Unborn]";
    } else if (err != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to get HEAD reference: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if(head_ref) git_reference_free(head_ref);
        return "";
    }
    if (git_reference_is_branch(head_ref) || git_reference_is_remote(head_ref)) {
        const char* branch_name_utf8 = git_reference_shorthand(head_ref);
        if (branch_name_utf8) {
            std::string current_branch = branch_name_utf8;
            git_reference_free(head_ref);
            return current_branch;
        } else {
            error_message = "Failed to get shorthand name for current branch reference.";
        }
    } else { // HEAD is not a symbolic reference, so it must be detached
        git_reference_free(head_ref); // We're done with the initial head_ref
        head_ref = nullptr;

        // HEAD is detached. Get the commit OID it points to.
        git_reference *detached_head_direct_ref = nullptr;
        // Re-fetch HEAD, this time knowing it's detached (or should resolve directly)
        int err_detached = git_repository_head(&detached_head_direct_ref, m_currentRepo);

        if (err_detached == 0 && detached_head_direct_ref != nullptr) {
            const git_oid *oid = git_reference_target(detached_head_direct_ref); // Get the OID it points to
            if (oid) {
                char sha_str[11]; // For a short SHA display, e.g., first 10 chars
                git_oid_tostr(sha_str, sizeof(sha_str) -1, oid); // -1 for null terminator space
                sha_str[10] = '\0'; // Ensure null termination
                git_reference_free(detached_head_direct_ref);
                return "[Detached HEAD @ " + std::string(sha_str) + "]";
            }
            git_reference_free(detached_head_direct_ref);
        }
        // Fallback if we couldn't get the OID for some reason
        return "[Detached HEAD]";
    }
    
    // Fallback or if shorthand failed earlier for symbolic ref
    if(head_ref) git_reference_free(head_ref); // Ensure it's freed if path above didn't
    return "[Unknown State]";
}