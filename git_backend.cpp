// git_backend.cpp (Corrected)
#include "git_backend.h"
#include <iostream>       // For potential std::cerr diagnostics
#include <ctime>          // For strftime
#include <algorithm>      // For std::min (if needed elsewhere)
#include <filesystem>     // For path checking in openRepository
#include <QProcess>       // For running git command line
#include <QTemporaryFile> // For temporary bundle file name
#include <QDir>
#include <QFileInfo>
#include <QDebug> // For qDebug

// GitBackend Constructor and Destructor
GitBackend::GitBackend()
{
    git_libgit2_init();
}

GitBackend::~GitBackend()
{
    freeCurrentRepo();
    git_libgit2_shutdown();
}

void GitBackend::freeCurrentRepo()
{
    if (m_currentRepo)
    {
        git_repository_free(m_currentRepo);
        m_currentRepo = nullptr;
        m_currentRepoPath.clear();
    }
}

// initializeRepository, openRepository, closeRepository, isRepositoryOpen, getCurrentRepositoryPath
// These should be the same as your previously working versions.

bool GitBackend::initializeRepository(const std::string &path, std::string &error_message)
{
    freeCurrentRepo();
    git_repository *repo = nullptr;
    int error = git_repository_init(&repo, path.c_str(), 0);
    if (error < 0)
    {
        const git_error *e = git_error_last();
        error_message = "Error initializing repository: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if (repo)
            git_repository_free(repo);
        return false;
    }
    m_currentRepo = repo;
    m_currentRepoPath = path;
    error_message = "Repository initialized and opened at: " + path;
    return true;
}

bool GitBackend::openRepository(const std::string &path, std::string &error_message)
{
    // Check if the path exists and is a directory before trying to open
    std::filesystem::path fs_path(path);
    if (!std::filesystem::exists(fs_path) || !std::filesystem::is_directory(fs_path))
    {
        error_message = "Error: Path does not exist or is not a directory: " + path;
        return false;
    }
    // Optional: Check if it looks like a git repository
    // if (!std::filesystem::exists(fs_path / ".git")) {
    //     // git_repository_open will also check, but this gives a more specific error message
    //     error_message = "Error: Directory does not contain a .git folder and may not be a repository: " + path;
    //     // return false; // Uncomment to fail early if .git is missing
    // }

    freeCurrentRepo();
    int error = git_repository_open(&m_currentRepo, path.c_str());
    if (error < 0)
    {
        const git_error *e = git_error_last();
        error_message = "Error opening repository: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return false;
    }
    m_currentRepoPath = path;
    error_message = "Repository opened successfully: " + path;
    return true;
}

bool GitBackend::createBundle(const std::string &outputDirStr, const std::string &bundleNameSuggestion, std::string &outBundleFilePath, std::string &error_message)
{
    if (!isRepositoryOpen())
    {
        error_message = "No repository is open to create a bundle from.";
        return false;
    }

    QDir outputDir(QString::fromStdString(outputDirStr));
    if (!outputDir.exists())
    {
        if (!outputDir.mkpath("."))
        {
            error_message = "Could not create output directory for bundle: " + outputDirStr;
            return false;
        }
    }

    QString safeBundleName = QString::fromStdString(bundleNameSuggestion);
    safeBundleName.remove(QRegExp(QStringLiteral("[^a-zA-Z0-9_.-]")));
    if (safeBundleName.isEmpty())
        safeBundleName = "repo";
    if (!safeBundleName.endsWith(".bundle"))
        safeBundleName += ".bundle";
    // Prevent leading hyphens or periods
    while (safeBundleName.startsWith("-") || safeBundleName.startsWith("."))
    {
        safeBundleName.remove(0, 1);
    }
    if (safeBundleName.isEmpty())
        safeBundleName = "repo.bundle";

    QString bundleFilePathQ = outputDir.filePath(safeBundleName);
    outBundleFilePath = bundleFilePathQ.toStdString();

    QProcess gitProcess;
    gitProcess.setWorkingDirectory(QString::fromStdString(m_currentRepoPath));
    QStringList arguments;
    arguments << "bundle" << "create" << bundleFilePathQ << "--all";

    qDebug() << "GitBackend: Running git" << arguments.join(" ") << "in" << QString::fromStdString(m_currentRepoPath);

    gitProcess.start("git", arguments);

    if (!gitProcess.waitForStarted(30000))
    {
        error_message = "Failed to start git bundle process: " + gitProcess.errorString().toStdString();
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        return false;
    }

    if (!gitProcess.waitForFinished(-1))
    {
        error_message = "Git bundle process did not finish.";
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        std::remove(outBundleFilePath.c_str());
        return false;
    }

    if (gitProcess.exitStatus() == QProcess::NormalExit && gitProcess.exitCode() == 0)
    {
        if (QFile(bundleFilePathQ).exists() && QFile(bundleFilePathQ).size() > 0)
        {
            error_message = "Bundle created successfully: " + outBundleFilePath;
            qInfo() << "GitBackend:" << QString::fromStdString(error_message);
            return true;
        }
        else
        {
            error_message = "Git bundle process finished successfully, but bundle file not found or is empty at: " + outBundleFilePath;
            qWarning() << "GitBackend:" << QString::fromStdString(error_message);
            qWarning() << "Git bundle stdout:" << QString(gitProcess.readAllStandardOutput());
            qWarning() << "Git bundle stderr:" << QString(gitProcess.readAllStandardError());
            if (QFile(bundleFilePathQ).exists())
                std::remove(outBundleFilePath.c_str());
            return false;
        }
    }
    else
    {
        error_message = "Git bundle process failed. Exit code: " + std::to_string(gitProcess.exitCode()) +
                        ". Stderr: " + QString(gitProcess.readAllStandardError()).toStdString();
        qWarning() << "GitBackend:" << QString::fromStdString(error_message);
        std::remove(outBundleFilePath.c_str());
        return false;
    }
}
void GitBackend::closeRepository()
{
    freeCurrentRepo();
}

bool GitBackend::isRepositoryOpen() const
{
    return m_currentRepo != nullptr;
}

std::string GitBackend::getCurrentRepositoryPath() const
{
    return m_currentRepoPath;
}

std::vector<CommitInfo> GitBackend::getCommitLog(int max_commits, std::string &error_message, const std::string &specific_ref_name_or_sha)
{
    std::vector<CommitInfo> log_entries;
    error_message.clear();
    int count = 0;

    if (!isRepositoryOpen())
    {
        error_message = "No repository open.";
        return log_entries;
    }

    git_revwalk *walk = nullptr;
    git_commit *commit_obj = nullptr;
    git_oid target_oid; // OID of the commit the specific_ref_name_or_sha resolves to

    if (git_revwalk_new(&walk, m_currentRepo) != 0)
    {
        const git_error *e = git_error_last();
        error_message = "Failed to create revwalk: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return log_entries;
    }
    git_revwalk_sorting(walk, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL);

    bool pushed_successfully = false;
    if (!specific_ref_name_or_sha.empty())
    {
        // Try to resolve the specific ref/sha to an OID
        git_object *obj = nullptr;
        int revparse_err = git_revparse_single(&obj, m_currentRepo, specific_ref_name_or_sha.c_str());

        if (revparse_err == 0 && obj != nullptr)
        {
            // Object found, try to peel it to a commit
            git_commit *commit_target = nullptr;
            int peel_err = git_object_peel(reinterpret_cast<git_object **>(&commit_target), obj, GIT_OBJECT_COMMIT);

            if (peel_err == 0 && commit_target != nullptr)
            {
                target_oid = *git_commit_id(commit_target);
                git_commit_free(commit_target); // Free the peeled commit object

                // Push the resolved commit OID to the revwalk
                if (git_revwalk_push(walk, &target_oid) == 0)
                {
                    pushed_successfully = true;
                }
                else
                {
                    const git_error *e = git_error_last();
                    error_message = "Failed to push resolved commit OID to revwalk: ";
                    error_message += (e && e->message) ? e->message : "Unknown error";
                }
            }
            else
            {
                // Could not peel to a commit
                const git_error *e = git_error_last();
                error_message = "Reference '" + specific_ref_name_or_sha + "' did not resolve to a commit: ";
                error_message += (peel_err == GIT_ENOTFOUND ? "Not a commit or peelable object." : (e && e->message ? e->message : "Unknown peeling error."));
            }
            git_object_free(obj); // Free the initial object
        }
        else
        {
            // git_revparse_single failed
            const git_error *e = git_error_last();
            error_message = "Failed to resolve reference '" + specific_ref_name_or_sha + "': ";
            error_message += (revparse_err == GIT_ENOTFOUND ? "Reference not found." : (e && e->message ? e->message : "Unknown error."));
        }
    }
    else
    { // specific_ref_name_or_sha is empty, use HEAD
        // Check if HEAD is valid (not an empty repo)
        if (git_repository_head_unborn(m_currentRepo) == 1)
        {
            // Repository is empty or HEAD is unborn. No commits to walk.
            git_revwalk_free(walk);
            return log_entries; // Correct: no commits, empty list is expected
        }
        // Push HEAD to the revwalk
        if (git_revwalk_push_head(walk) == 0)
        {
            pushed_successfully = true;
        }
        else
        {
            const git_error *e = git_error_last();
            error_message = "Failed to push HEAD to revwalk: ";
            error_message += (e && e->message) ? e->message : "Unknown error";
        }
    }

    if (!pushed_successfully)
    {
        // error_message should have been set by the failing push attempt.
        if (walk)
            git_revwalk_free(walk);
        return log_entries;
    }

    git_oid loop_oid;
    int error_walk;
    // Iterate through the commits in the revwalk
    while ((error_walk = git_revwalk_next(&loop_oid, walk)) == 0 && (max_commits <= 0 || count < max_commits))
    {
        // Lookup the commit object
        if (git_commit_lookup(&commit_obj, m_currentRepo, &loop_oid) != 0)
        {
            const git_error *e = git_error_last();
            std::string commit_load_err_msg = "Warning: Failed to lookup commit ";
            commit_load_err_msg += git_oid_tostr_s(&loop_oid);
            commit_load_err_msg += ": ";
            commit_load_err_msg += (e && e->message) ? e->message : "Unknown error";
            std::cerr << commit_load_err_msg << std::endl; // Log to console for debugging
            // Append warning to error_message if not already set, or concatenate
            if (error_message.empty())
                error_message = commit_load_err_msg;
            else
                error_message += " | " + commit_load_err_msg;

            if (commit_obj)
                git_commit_free(commit_obj);
            commit_obj = nullptr;
            continue; // Try to get the next commit from the walk
        }

        // Extract commit information
        CommitInfo info;
        char sha_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(sha_str, sizeof(sha_str), git_commit_id(commit_obj)); // Use git_oid_tostr for null termination
        info.sha = sha_str;

        const git_signature *author = git_commit_author(commit_obj);
        if (author)
        {
            info.author_name = (author->name != nullptr) ? author->name : "N/A";
            info.author_email = (author->email != nullptr) ? author->email : "N/A";
            // Format date
            char time_buf[64];
            time_t t = (time_t)author->when.time;
            struct tm *lt = localtime(&t); // Use localtime for local timezone
            if (lt && strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S %Z", lt) > 0)
            { // Include timezone
                info.date = time_buf;
            }
            else
            {
                info.date = "Invalid date";
            }
        }
        else
        {
            info.author_name = "N/A";
            info.author_email = "N/A";
            info.date = "N/A";
        }

        const char *summary_cstr = git_commit_summary(commit_obj);
        info.summary = (summary_cstr != nullptr) ? summary_cstr : "[no summary]";

        log_entries.push_back(info);

        git_commit_free(commit_obj); // Free the commit object after use
        commit_obj = nullptr;        // Set to nullptr to avoid double-free
        count++;
    }

    // Check for errors during the walk itself (other than GIT_ITEROVER)
    if (error_walk < 0 && error_walk != GIT_ITEROVER)
    {
        const git_error *e = git_error_last();
        std::string revwalk_err_str = "Error during revwalk: ";
        revwalk_err_str += (e && e->message) ? e->message : "Unknown error";
        if (error_message.empty())
            error_message = revwalk_err_str;
        else
            error_message = revwalk_err_str + " | " + error_message;
    }

    if (commit_obj)
        git_commit_free(commit_obj); // Should be null by loop end, but safety check
    git_revwalk_free(walk);          // Free the revwalk object

    // If no entries were collected and no specific error was set, it means no commits were found for the ref.
    if (log_entries.empty() && error_message.empty())
    {
        error_message = "No commits found for ";
        if (specific_ref_name_or_sha.empty())
        {
            error_message += "current HEAD (empty repository?).";
        }
        else
        {
            error_message += "'" + specific_ref_name_or_sha + "'.";
        }
    }
    return log_entries;
}

// listBranches - lists local and remote branches. Does not list tags here.
std::vector<std::string> GitBackend::listBranches(BranchType type, std::string &error_message)
{
    std::vector<std::string> refs; // Renamed to refs as it can include more than just branches
    error_message.clear();
    if (!isRepositoryOpen())
    {
        error_message = "No repository open.";
        return refs;
    }

    // List Branches (Local and/or Remote)
    git_branch_iterator *it = nullptr;
    git_branch_t branch_flags = (type == BranchType::ALL) ? (git_branch_t)(GIT_BRANCH_LOCAL | GIT_BRANCH_REMOTE) : static_cast<git_branch_t>(type);

    if (git_branch_iterator_new(&it, m_currentRepo, branch_flags) == 0)
    {
        git_reference *ref = nullptr;
        git_branch_t iterated_branch_type;
        const char *branch_name_utf8 = nullptr;
        while (git_branch_next(&ref, &iterated_branch_type, it) == 0)
        {
            if (git_branch_name(&branch_name_utf8, ref) == 0)
            {
                refs.push_back(branch_name_utf8);
            }
            else
            {
                qWarning() << "GitBackend: Failed to get branch name for ref:" << git_reference_name(ref) << "Error:" << (git_error_last() ? git_error_last()->message : "Unknown");
            }
            git_reference_free(ref);
            ref = nullptr;
        }
        git_branch_iterator_free(it);
    }
    else
    {
        const git_error *e = git_error_last();
        error_message = "Failed to create branch iterator: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        return refs;
    }

    // Additionally, list tags if type is ALL
    if (type == BranchType::ALL)
    {
        git_strarray tag_names;
        if (git_tag_list(&tag_names, m_currentRepo) == 0)
        {
            for (size_t i = 0; i < tag_names.count; ++i)
            {
                refs.push_back("tags/" + std::string(tag_names.strings[i])); // Prefix with "tags/" for clarity
            }
            git_strarray_free(&tag_names);
        }
        else
        {
            const git_error *e = git_error_last();
            // Log tag listing error as a warning, don't fail the whole function
            qWarning() << "GitBackend: Failed to list tags:" << (e && e->message ? e->message : "Unknown error");
        }
    }

    return refs; // Return combined list of branches and tags
}

bool GitBackend::checkoutBranch(const std::string &ref_name_from_ui, std::string &error_message)
{
    error_message.clear();
    if (!isRepositoryOpen())
    {
        error_message = "No repository open.";
        return false;
    }

    git_object *target_obj = nullptr;
    int revparse_err = git_revparse_single(&target_obj, m_currentRepo, ref_name_from_ui.c_str());

    if (revparse_err != 0 || !target_obj)
    {
        const git_error *e = git_error_last();
        error_message = "Failed to resolve reference '" + ref_name_from_ui + "': ";
        error_message += (revparse_err == GIT_ENOTFOUND ? "Reference not found." : (e && e->message ? e->message : "Unknown error."));
        if (target_obj)
            git_object_free(target_obj);
        return false;
    }

    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    opts.checkout_strategy = GIT_CHECKOUT_SAFE; // Prevent overwriting local changes

    int checkout_err = 0;

    // First, try to peel the object to a commit. This works for commits, tags, and branch tips.
    git_commit *commit_target = nullptr;
    int peel_err = git_object_peel(reinterpret_cast<git_object **>(&commit_target), target_obj, GIT_OBJECT_COMMIT);

    if (peel_err == 0 && commit_target != nullptr)
    {
        // We successfully peeled to a commit (this is the target commit for the checkout).

        // Check if the resolved reference is a remote-tracking branch (e.g., "origin/main")
        // If so, the common user expectation is to create a local tracking branch.
        // If it's a local branch, tag, or raw SHA, the standard checkout applies (symbolic or detached).

        // To check if it's a remote branch *using the original ref_name_from_ui*, we can look up the reference directly.
        git_reference *resolved_ref = nullptr;
        // Try looking up the reference name directly. This succeeds if ref_name_from_ui *was* a reference name.
        int ref_lookup_err = git_reference_lookup(&resolved_ref, m_currentRepo, ref_name_from_ui.c_str());

        bool is_remote_branch_ref = false;
        if (ref_lookup_err == 0 && resolved_ref != nullptr)
        {
            // Successfully looked up a reference. Is it a remote branch?
            is_remote_branch_ref = git_reference_is_remote(resolved_ref);
        }
        if (resolved_ref)
            git_reference_free(resolved_ref); // Free the looked-up ref

        if (is_remote_branch_ref)
        {
            // User selected a remote-tracking branch (e.g., "origin/main").
            // We need to create a local branch tracking it and check that out.
            const char *shorthand = git_reference_shorthand(reinterpret_cast<git_reference *>(target_obj)); // Get shorthand like "origin/main"
            std::string remote_shorthand = shorthand ? shorthand : ref_name_from_ui;                        // Fallback if shorthand fails

            size_t first_slash = remote_shorthand.find('/');
            std::string desired_local_branch_name = remote_shorthand.substr(first_slash + 1); // e.g. "main" from "origin/main"

            // Avoid problematic local branch names
            if (desired_local_branch_name == "HEAD")
            {
                error_message = "Cannot create a local branch named 'HEAD'. Please select a specific remote branch (e.g., origin/main).";
                checkout_err = -1; // Mark as error
            }
            else
            {
                // Check if the local branch already exists
                git_reference *existing_local_ref = nullptr;
                int local_lookup_err = git_branch_lookup(&existing_local_ref, m_currentRepo, desired_local_branch_name.c_str(), GIT_BRANCH_LOCAL);

                if (local_lookup_err == 0 && existing_local_ref != nullptr)
                {
                    // Local branch already exists, just check it out symbolically
                    git_reference_free(existing_local_ref);
                    qDebug() << "GitBackend: Local branch" << QString::fromStdString(desired_local_branch_name) << "already exists. Checking it out.";
                    checkout_err = git_repository_set_head(m_currentRepo, ("refs/heads/" + desired_local_branch_name).c_str());
                    if (checkout_err == 0)
                    {
                        // Now update the worktree to match the head commit
                        int worktree_err = git_checkout_head(m_currentRepo, &opts);
                        if (worktree_err == 0)
                        {
                            error_message = "Switched to existing local branch: " + desired_local_branch_name;
                        }
                        else
                        {
                            const git_error *e = git_error_last();
                            std::string prev_msg = "Switched to existing local branch '" + desired_local_branch_name + "', but failed to update worktree: ";
                            error_message = prev_msg + (e && e->message ? e->message : "Unknown error. (Local changes might be in the way)");
                            checkout_err = worktree_err; // Propagate worktree error
                        }
                    }
                    else
                    {
                        const git_error *e = git_error_last();
                        error_message = "Failed to set HEAD to existing local branch '" + desired_local_branch_name + "': ";
                        error_message += (e && e->message) ? e->message : "Unknown error.";
                    }
                }
                else if (local_lookup_err == GIT_ENOTFOUND)
                {
                    // Local branch does NOT exist, create it tracking the remote
                    qDebug() << "GitBackend: Local branch" << QString::fromStdString(desired_local_branch_name) << "not found. Creating tracking branch.";

                    git_reference *newly_created_local_branch_ref = nullptr;
                    // Create the new local branch pointing to the remote branch's tip commit
                    int branch_create_err = git_branch_create(&newly_created_local_branch_ref, m_currentRepo, desired_local_branch_name.c_str(), commit_target, 0 /*force=false*/);

                    if (branch_create_err != 0)
                    {
                        const git_error *e = git_error_last();
                        error_message = "Failed to create local tracking branch '" + desired_local_branch_name + "' for '" + remote_shorthand + "': ";
                        error_message += (e && e->message) ? e->message : "Unknown error.";
                        checkout_err = -1;
                    }
                    else
                    {
                        // Set the upstream tracking branch
                        int set_upstream_err = git_branch_set_upstream(newly_created_local_branch_ref, remote_shorthand.c_str());
                        if (set_upstream_err != 0)
                        {
                            const git_error *e = git_error_last();
                            qWarning() << "GitBackend: Failed to set upstream for local branch" << QString::fromStdString(desired_local_branch_name) << "to" << QString::fromStdString(remote_shorthand) << ":" << (e && e->message ? e->message : "Unknown error");
                            // This is a warning, checkout can still proceed
                        }

                        // Checkout the newly created local branch (updates HEAD and worktree)
                        int set_head_err = git_repository_set_head(m_currentRepo, git_reference_name(newly_created_local_branch_ref));
                        if (set_head_err != 0)
                        {
                            const git_error *e = git_error_last();
                            error_message = "Failed to set HEAD to newly created branch '" + desired_local_branch_name + "': ";
                            error_message += (e && e->message) ? e->message : "Unknown error.";
                            checkout_err = -1;
                        }
                        else
                        {
                            // Checkout the worktree to match the new HEAD
                            checkout_err = git_checkout_head(m_currentRepo, &opts);
                            if (checkout_err == 0)
                            {
                                error_message = "Created and checked out local branch '" + desired_local_branch_name + "' tracking '" + remote_shorthand + "'";
                            }
                            else
                            {
                                const git_error *e = git_error_last();
                                std::string previous_message = "Created branch '" + desired_local_branch_name + "' tracking '" + remote_shorthand + "'. ";
                                error_message = previous_message + "Then, failed to update working directory: ";
                                error_message += (e && e->message) ? e->message : "Changes might prevent checkout.";
                            }
                        }
                        git_reference_free(newly_created_local_branch_ref); // Free the new reference
                    }
                }
                else
                { // Some other error looking up local branch
                    const git_error *e = git_error_last();
                    error_message = "Error looking up local branch '" + desired_local_branch_name + "': ";
                    error_message += (e && e->message) ? e->message : "Unknown error";
                    checkout_err = -1;
                    if (existing_local_ref)
                        git_reference_free(existing_local_ref);
                }
            }
        }
        else
        {
            // User selected a local branch, tag, or raw SHA.
            // Checkout the target commit and set HEAD appropriately.

            // Checkout the target commit (updates worktree)
            checkout_err = git_checkout_tree(m_currentRepo, reinterpret_cast<git_object *>(commit_target), &opts);

            if (checkout_err == 0)
            {
                // If the original object was a reference (local branch or tag),
                // set HEAD symbolically to that reference.
                // If it was a raw commit object (SHA), set HEAD detached to the commit OID.
                git_reference *original_ref = nullptr;
                // Try looking up the original string as a reference name.
                int original_ref_lookup_err = git_reference_lookup(&original_ref, m_currentRepo, ref_name_from_ui.c_str());

                if (original_ref_lookup_err == 0 && original_ref != nullptr)
                {
                    // Original was a reference (local branch or tag)
                    int set_head_err = git_repository_set_head(m_currentRepo, git_reference_name(original_ref));
                    if (set_head_err != 0)
                    {
                        const git_error *e = git_error_last();
                        std::string warning_msg = "Warning: Checkout successful, but failed to set HEAD to reference '" + ref_name_from_ui + "': ";
                        warning_msg += (e && e->message) ? e->message : "Unknown error.";
                        error_message = warning_msg; // Return as error message, but checkout happened
                        qWarning() << "GitBackend:" << QString::fromStdString(warning_msg);
                        checkout_err = set_head_err; // Propagate the HEAD error too
                    }
                    else
                    {
                        error_message = "Checked out reference: " + ref_name_from_ui;
                    }
                    git_reference_free(original_ref); // Free the original reference
                }
                else
                {
                    // Original was not a reference (must have been a raw SHA that peeled to itself).
                    // Set HEAD detached to the commit OID.
                    int set_head_err = git_repository_set_head_detached(m_currentRepo, git_object_id(reinterpret_cast<git_object *>(commit_target)));
                    if (set_head_err != 0)
                    {
                        const git_error *e = git_error_last();
                        std::string warning_msg = "Warning: Checkout successful, but failed to set HEAD to detached state: ";
                        warning_msg += (e && e->message) ? e->message : "Unknown error.";
                        error_message = warning_msg; // Return as error message, but checkout happened
                        qWarning() << "GitBackend:" << QString::fromStdString(warning_msg);
                        checkout_err = set_head_err; // Propagate the HEAD error too
                    }
                    else
                    {
                        char sha_str[11];
                        git_oid_nfmt(sha_str, sizeof(sha_str), git_object_id(reinterpret_cast<git_object *>(commit_target)));
                        error_message = "Checked out commit: " + std::string(sha_str) + " (Detached HEAD)";
                    }
                }
            }
        }

        git_commit_free(commit_target); // Free the peeled commit object
    }
    else
    {
        // Could not peel the resolved object to a commit.
        // This means the resolved object is not a commit, tag, or branch tip.
        const git_error *e = git_error_last();
        error_message = "Reference '" + ref_name_from_ui + "' resolved to an unexpected object type (not commit/tag/branch tip): ";
        error_message += (e && e->message) ? e->message : "Unknown error.";
        checkout_err = -1; // Mark as error
    }

    git_object_free(target_obj); // Free the object resolved by revparse_single

    if (checkout_err != 0 && error_message.empty())
    {
        const git_error *e = git_error_last();
        error_message = "Checkout failed: ";
        error_message += (e && e->message) ? e->message : "Unknown error.";
    }

    // Return true only if the final checkout operation itself was successful (ignoring HEAD setting warnings if checkout_err == 0)
    // If setting HEAD failed *after* a successful worktree checkout, we might still return true depending on desired strictness.
    // Returning true only if checkout_err is 0 seems the most robust.
    return checkout_err == 0;
}

std::string GitBackend::getCurrentBranch(std::string &error_message)
{
    error_message.clear();
    if (!isRepositoryOpen())
    {
        error_message = "No repository open.";
        return "";
    }
    git_reference *head_ref = nullptr;
    int err = git_repository_head(&head_ref, m_currentRepo);

    if (err == GIT_EUNBORNBRANCH)
    {
        if (head_ref)
            git_reference_free(head_ref);
        return "[Unborn START]";
    }
    else if (err == GIT_ENOTFOUND)
    {
        if (head_ref)
            git_reference_free(head_ref);
        error_message = "Repository HEAD reference not found.";
        return "[Unknown HEAD State]";
    }
    else if (err != 0)
    {
        const git_error *e = git_error_last();
        error_message = "Failed to get HEAD reference: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if (head_ref)
            git_reference_free(head_ref);
        return "[Error]";
    }

    std::string result = "[Unknown State]";

    // Check reference type using git_reference_type
    git_ref_t ref_type = git_reference_type(head_ref);
    if (ref_type == GIT_REFERENCE_SYMBOLIC)
    {
        // It's a symbolic ref (like refs/heads/main or refs/remotes/origin/main)
        const char *shorthand = git_reference_shorthand(head_ref);
        if (shorthand)
        {
            result = shorthand;
        }
        else
        {
            // Fallback to full name if shorthand fails
            const char *ref_name = git_reference_name(head_ref);
            if (ref_name)
            {
                result = ref_name; // e.g., "refs/heads/main"
            }
            else
            {
                error_message = "Failed to get name for symbolic HEAD reference.";
                result = "[Symbolic HEAD]";
            }
        }
    }
    else if (ref_type == GIT_REFERENCE_DIRECT)
    {
        // It's a direct OID reference (Detached HEAD)
        const git_oid *oid = git_reference_target(head_ref);
        if (oid)
        {
            char sha_str[11];
            git_oid_nfmt(sha_str, sizeof(sha_str), oid);
            result = "[Detached HEAD @ " + std::string(sha_str) + "]";
        }
        else
        {
            error_message = "Failed to get OID for direct HEAD reference.";
            result = "[Detached HEAD]";
        }
    }
    else
    {
        // Should not happen for HEAD reference
        error_message = "HEAD reference is of unexpected type.";
        result = "[Unexpected HEAD Type]";
    }

    git_reference_free(head_ref);
    return result;
}