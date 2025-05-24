#include "git_backend.h"
#include <iostream> // For basic error printing if needed

GitBackend::GitBackend() {
    // Initialize libgit2. This must be called before any other libgit2 function.
    // It's reference-counted, so multiple calls are fine.
    git_libgit2_init();
}

GitBackend::~GitBackend() {
    // Shutdown libgit2. Call this when you're done using libgit2.
    // It's reference-counted, matching calls to init.
    git_libgit2_shutdown();
}

bool GitBackend::initializeRepository(const std::string& path, std::string& error_message) {
    git_repository *repo = nullptr;
    int error = git_repository_init(&repo, path.c_str(), 0); // 0 for a non-bare repository

    if (error < 0) {
        const git_error *e = git_error_last();
        error_message = "Error initializing repository: ";
        error_message += (e && e->message) ? e->message : "Unknown error";
        if (repo) { // Should not happen if init failed, but good practice
            git_repository_free(repo);
        }
        return false;
    }

    // If successful, repo now points to the initialized repository
    // We should free it as we are done with it for this simple function.
    if (repo) {
        git_repository_free(repo);
    }
    error_message = "Repository initialized successfully at: " + path;
    return true;
}