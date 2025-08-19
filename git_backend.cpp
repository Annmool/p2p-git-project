#include "git_backend.h"
#include <iostream>
#include <ctime>
#include <algorithm>
#include <filesystem>
#include <QProcess>
#include <QTemporaryFile>
#include <QDir>
#include <QFileInfo>
#include <QDebug>

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
        error_message = "Error initializing repository: " + std::string((e && e->message) ? e->message : "Unknown error");
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
        error_message = "Error opening repository: " + std::string((e && e->message) ? e->message : "Unknown error");
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
    gitProcess.start("git", arguments);
    if (!gitProcess.waitForStarted(-1)) {
        error_message = "Failed to start git bundle process: " + gitProcess.errorString().toStdString();
        return false;
    }
    if (!gitProcess.waitForFinished(-1)) {
        error_message = "Git bundle process timed out or did not finish: " + gitProcess.errorString().toStdString();
        return false;
    }
    if (gitProcess.exitStatus() == QProcess::NormalExit && gitProcess.exitCode() == 0) {
        if (QFile(bundleFilePathQ).exists()) {
            error_message = "Bundle created successfully: " + outBundleFilePath;
            return true;
        } else {
            error_message = "Git bundle process finished but bundle file not found at: " + outBundleFilePath;
            return false;
        }
    } else {
        error_message = "Git bundle process failed. Exit code: " + std::to_string(gitProcess.exitCode()) +
                        ". Stderr: " + QString(gitProcess.readAllStandardError()).toStdString();
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

    git_revwalk_new(&walk, m_currentRepo);
    git_revwalk_sorting(walk, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL);

    if (specific_ref_name_or_sha.empty()) {
        if (git_repository_head_unborn(m_currentRepo) != 1) {
            git_revwalk_push_head(walk);
        }
    } else {
        git_object *obj = nullptr;
        if (git_revparse_single(&obj, m_currentRepo, specific_ref_name_or_sha.c_str()) == 0) {
            git_revwalk_push(walk, git_object_id(obj));
            git_object_free(obj);
        } else {
            error_message = "Failed to find reference: " + specific_ref_name_or_sha;
            git_revwalk_free(walk);
            return log_entries;
        }
    }
    
    git_oid loop_oid;
    while (git_revwalk_next(&loop_oid, walk) == 0 && (max_commits <= 0 || count < max_commits)) {
        if (git_commit_lookup(&commit_obj, m_currentRepo, &loop_oid) != 0) {
            continue; 
        }

        CommitInfo info;
        info.sha = git_oid_tostr_s(&loop_oid);
        const git_signature *author = git_commit_author(commit_obj);
        if (author) {
            info.author_name = author->name ? author->name : "";
            info.author_email = author->email ? author->email : "";
            char time_buf[64];
            time_t t = (time_t)author->when.time;
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
            info.date = time_buf;
        }
        info.summary = git_commit_summary(commit_obj);
        log_entries.push_back(info);
        git_commit_free(commit_obj);
        count++;
    }
    
    git_revwalk_free(walk);
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
    git_branch_iterator_new(&it, m_currentRepo, static_cast<git_branch_t>(type));
    
    git_reference *ref = nullptr;
    git_branch_t iterated_branch_type;
    const char *branch_name_utf8 = nullptr;
    while (git_branch_next(&ref, &iterated_branch_type, it) == 0) {
        if (git_branch_name(&branch_name_utf8, ref) == 0) {
            branches.push_back(branch_name_utf8);
        }
        git_reference_free(ref);
    }
    git_branch_iterator_free(it);
    return branches;
}

bool GitBackend::checkoutBranch(const std::string& branch_name_from_ui, std::string& error_message) {
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return false;
    }
    
    git_object* treeish = nullptr;
    if (git_revparse_single(&treeish, m_currentRepo, branch_name_from_ui.c_str()) != 0) {
        const git_error* e = git_error_last();
        error_message = "Cannot find branch/commit: " + std::string(e ? e->message : "Unknown error");
        return false;
    }

    git_checkout_options opts = GIT_CHECKOUT_OPTIONS_INIT;
    opts.checkout_strategy = GIT_CHECKOUT_SAFE;

    if (git_checkout_tree(m_currentRepo, treeish, &opts) != 0) {
        const git_error* e = git_error_last();
        error_message = "Checkout failed: " + std::string(e ? e->message : "Unknown error");
        git_object_free(treeish);
        return false;
    }

    std::string ref_name = "refs/heads/" + branch_name_from_ui;
    git_repository_set_head(m_currentRepo, ref_name.c_str());
    
    git_object_free(treeish);
    return true;
}

std::string GitBackend::getCurrentBranch(std::string& error_message) {
    if (!isRepositoryOpen()) {
        error_message = "No repository open.";
        return "";
    }
    git_reference *head = nullptr;
    if (git_repository_head(&head, m_currentRepo) != 0) {
        return "[unborn]";
    }

    const char* branch_name = git_reference_shorthand(head);
    std::string result = branch_name ? branch_name : "[detached]";
    git_reference_free(head);
    return result;
}

bool GitBackend::fetchFromBundle(const std::string& bundlePath, std::string& error_message) {
    QProcess gitProcess;
    gitProcess.setWorkingDirectory(QString::fromStdString(m_currentRepoPath));
    QStringList args;
    args << "fetch" << QString::fromStdString(bundlePath) << "refs/*:refs/remotes/origin/*" << "--prune";
    gitProcess.start("git", args);
    if (!gitProcess.waitForFinished(-1)) {
        error_message = "Git fetch from bundle timed out.";
        return false;
    }
    if (gitProcess.exitCode() != 0) {
        error_message = "Git fetch from bundle failed: " + gitProcess.readAllStandardError().toStdString();
        return false;
    }
    return true;
}

std::vector<FileStatus> GitBackend::getRepositoryStatus(std::string& error_message) {
    std::vector<FileStatus> statuses;
    if (!isRepositoryOpen()) { error_message = "No repository open."; return statuses; }

    git_status_list* status_list = nullptr;
    git_status_options status_opts = GIT_STATUS_OPTIONS_INIT;
    status_opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    status_opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX | GIT_STATUS_OPT_SORT_CASE_SENSITIVELY;

    if (git_status_list_new(&status_list, m_currentRepo, &status_opts) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to get repository status: " + std::string(e ? e->message : "Unknown");
        return statuses;
    }

    for (size_t i = 0; i < git_status_list_entrycount(status_list); ++i) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (entry->status == GIT_STATUS_CURRENT) continue;
        
        FileStatus fs;
        fs.git_status = entry->status;
        if (entry->index_to_workdir) fs.path = entry->index_to_workdir->new_file.path;
        else if (entry->head_to_index) fs.path = entry->head_to_index->new_file.path;
        
        statuses.push_back(fs);
    }
    git_status_list_free(status_list);
    return statuses;
}

bool GitBackend::stagePath(const std::string& path, std::string& error_message) {
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }
    git_index *index = nullptr;
    git_repository_index(&index, m_currentRepo);
    if (git_index_add_bypath(index, path.c_str()) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to stage file: " + std::string(e ? e->message : "Unknown");
        git_index_free(index);
        return false;
    }
    git_index_write(index);
    git_index_free(index);
    return true;
}

bool GitBackend::unstagePath(const std::string& path, std::string& error_message) {
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }

    git_reference *head_ref = nullptr;
    git_object *head_commit_obj = nullptr;
    
    int error = git_repository_head(&head_ref, m_currentRepo);

    if (error == GIT_EUNBORNBRANCH || error == GIT_ENOTFOUND) {
        git_index* index = nullptr;
        git_repository_index(&index, m_currentRepo);
        git_index_remove_bypath(index, path.c_str());
        git_index_write(index);
        git_index_free(index);
        if (head_ref) git_reference_free(head_ref);
        return true;
    }
    
    char* path_array[] = {const_cast<char*>(path.c_str())};
    git_strarray pathspec = { path_array, 1 };

    if (git_reference_peel(&head_commit_obj, head_ref, GIT_OBJECT_COMMIT) != 0) {
        error_message = "Could not get HEAD commit to unstage changes.";
        git_reference_free(head_ref);
        return false;
    }
    
    if (git_reset_default(m_currentRepo, head_commit_obj, &pathspec) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to unstage file: " + std::string(e ? e->message : "Unknown");
        git_reference_free(head_ref);
        git_object_free(head_commit_obj);
        return false;
    }

    git_reference_free(head_ref);
    git_object_free(head_commit_obj);
    return true;
}

bool GitBackend::stageAll(std::string& error_message) {
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }
    git_index *index = nullptr;
    git_repository_index(&index, m_currentRepo);
    if (git_index_add_all(index, nullptr, GIT_INDEX_ADD_DEFAULT, nullptr, nullptr) != 0) {
        const git_error *e = git_error_last();
        error_message = "Failed to stage all files: " + std::string(e ? e->message : "Unknown");
        git_index_free(index);
        return false;
    }
    git_index_write(index);
    git_index_free(index);
    return true;
}

bool GitBackend::unstageAll(std::string& error_message) {
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }
    git_reference *head_ref = nullptr;
    git_object *head_commit_obj = nullptr;
    
    git_repository_head(&head_ref, m_currentRepo);
    
    if (git_reference_peel(&head_commit_obj, head_ref, GIT_OBJECT_COMMIT) != 0) {
        error_message = "Could not get HEAD commit to unstage changes.";
        if (head_ref) git_reference_free(head_ref);
        return false;
    }

    if (git_reset_default(m_currentRepo, head_commit_obj, nullptr) != 0) {
        const git_error* e = git_error_last();
        error_message = "Failed to unstage all files: " + std::string(e ? e->message : "Unknown");
        if (head_ref) git_reference_free(head_ref);
        git_object_free(head_commit_obj);
        return false;
    }
    
    if (head_ref) git_reference_free(head_ref);
    git_object_free(head_commit_obj);
    return true;
}

bool GitBackend::commitChanges(const std::string& message, const std::string& author_name, const std::string& author_email, std::string& error_message) {
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }

    git_oid tree_oid, commit_oid;
    git_index *index = nullptr;
    git_tree *tree = nullptr;
    git_signature *author = nullptr;
    git_commit *parent = nullptr;
    git_reference *head = nullptr;

    auto cleanup = [&]() {
        git_index_free(index);
        git_tree_free(tree);
        git_signature_free(author);
        git_commit_free(parent);
        git_reference_free(head);
    };

    if (git_repository_index(&index, m_currentRepo) != 0) { error_message = "Could not get repository index."; cleanup(); return false; }
    if (git_index_write_tree(&tree_oid, index) != 0) { error_message = "Could not write index to tree."; cleanup(); return false; }
    if (git_tree_lookup(&tree, m_currentRepo, &tree_oid) != 0) { error_message = "Could not look up newly created tree."; cleanup(); return false; }
    if (git_signature_now(&author, author_name.c_str(), author_email.c_str()) != 0) { error_message = "Could not create commit signature."; cleanup(); return false; }

    if (git_repository_head(&head, m_currentRepo) == 0) {
        git_object* parent_obj = nullptr;
        git_reference_peel(&parent_obj, head, GIT_OBJECT_COMMIT);
        parent = (git_commit*)parent_obj;
    }

    if (git_commit_create_v(&commit_oid, m_currentRepo, "HEAD", author, author, nullptr, message.c_str(), tree, parent ? 1 : 0, parent) != 0) {
        const git_error* e = git_error_last();
        error_message = "Failed to create commit: " + std::string(e ? e->message : "Unknown");
        cleanup();
        return false;
    }
    
    cleanup();
    return true;
}

bool GitBackend::createDiffBundle(const std::string& output_path, const std::string& local_branch, const std::string& remote_branch_base, std::string& error_message)
{
    if (!isRepositoryOpen()) { error_message = "No repository open."; return false; }
    QProcess gitProcess;
    gitProcess.setWorkingDirectory(QString::fromStdString(m_currentRepoPath));
    QStringList args;
    args << "bundle" << "create" << QString::fromStdString(output_path) << QString::fromStdString(local_branch) << QString("^%1").arg(QString::fromStdString(remote_branch_base));
    gitProcess.start("git", args);
    if (!gitProcess.waitForFinished(60000)) { error_message = "Git diff bundle process timed out."; return false; }

    if (gitProcess.exitStatus() == QProcess::NormalExit && gitProcess.exitCode() == 0) {
        if (QFile(QString::fromStdString(output_path)).size() > 0) return true;
        error_message = "No new commits to bundle.";
        QFile::remove(QString::fromStdString(output_path));
        return false;
    }
    error_message = "Git diff bundle process failed. Stderr: " + QString(gitProcess.readAllStandardError()).toStdString();
    return false;
}

bool GitBackend::applyBundle(const std::string& bundle_path, std::string& error_message)
{
    if (!isRepositoryOpen()) { error_message = "No repository open to apply bundle to."; return false; }
    QProcess gitProcess;
    gitProcess.setWorkingDirectory(QString::fromStdString(m_currentRepoPath));
    QStringList args;
    args << "pull" << QString::fromStdString(bundle_path) << "--no-rebase"; // Use merge strategy
    gitProcess.start("git", args);
    if (!gitProcess.waitForFinished(-1)) { error_message = "Git pull from bundle process timed out."; return false; }

    QString stderr_output = gitProcess.readAllStandardError();
    if (gitProcess.exitStatus() == QProcess::NormalExit && gitProcess.exitCode() == 0) {
        error_message = "Bundle applied successfully. " + QString(gitProcess.readAllStandardOutput()).toStdString();
        return true;
    }
    error_message = "Failed to apply bundle. Stderr: " + stderr_output.toStdString();
    return false;
}