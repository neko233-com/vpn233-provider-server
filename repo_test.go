package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withGitRunner(t *testing.T, runner gitRunner) func() {
	t.Helper()
	previous := runGitCommand
	runGitCommand = runner
	return func() {
		runGitCommand = previous
	}
}

func withWorkingDir(t *testing.T, dir string) func() {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	return func() {
		_ = os.Chdir(previous)
	}
}

func TestNormalizeRepoDefaults(t *testing.T) {
	cfg := normalizeRepoDefaults(ServerConfig{})
	if cfg.SubscribeRepoURL != defaultSubscribeRepoURL {
		t.Fatalf("expect default repo url %q, got %q", defaultSubscribeRepoURL, cfg.SubscribeRepoURL)
	}
	if cfg.SubscribeRepoPath != defaultSubscribeRepoDir {
		t.Fatalf("expect default repo path %q, got %q", defaultSubscribeRepoDir, cfg.SubscribeRepoPath)
	}
	if cfg.SubscribeRepoBranch != defaultSubscribeRepoMain {
		t.Fatalf("expect default branch %q, got %q", defaultSubscribeRepoMain, cfg.SubscribeRepoBranch)
  }
}

func TestInspectGitContextRootAndSubmodule(t *testing.T) {
	root := t.TempDir()
	restore := withWorkingDir(t, root)
	defer restore()

	mock := func(_ string, args ...string) (string, error) {
		switch {
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--is-inside-work-tree":
			return "true", nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--show-toplevel":
			return root, nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--show-superproject-working-tree":
			return "", nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--git-dir":
			return ".git", nil
		}
		return "", nil
	}
	restoreGit := withGitRunner(t, mock)
	defer restoreGit()

	ctx, err := inspectGitContext(".")
	if err != nil {
		t.Fatalf("inspect git context error: %v", err)
	}
	if !ctx.InsideWorkTree {
		t.Fatal("expect inside work tree")
	}
	if !ctx.IsRootRepository {
		t.Fatal("expect root repository")
	}

	mockSub := func(_ string, args ...string) (string, error) {
		switch {
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--is-inside-work-tree":
			return "true", nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--show-toplevel":
			return root, nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--show-superproject-working-tree":
			return filepath.Join(root, "super"), nil
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "--git-dir":
			return ".git", nil
		}
		return "", nil
	}

	restoreGit()
	restoreGit = withGitRunner(t, mockSub)
	ctxSub, err := inspectGitContext(".")
	if err != nil {
		t.Fatalf("inspect git context error: %v", err)
	}
	if !ctxSub.IsSubmodule {
		t.Fatal("expect submodule context")
	}
}

func TestInspectRepoStateAndSyncStatus(t *testing.T) {
	temp := t.TempDir()
	restoreWD := withWorkingDir(t, temp)
	defer restoreWD()

	restoreGit := withGitRunner(t, func(_ string, args ...string) (string, error) {
		return "", errors.New("not a git repository")
	})
	defer restoreGit()

	cfg := normalizeRepoDefaults(ServerConfig{})
	check, ctx, err := inspectRepoState(cfg)
	if err != nil {
		t.Fatalf("inspect repo state error: %v", err)
	}
	if ctx.InsideWorkTree {
		t.Fatal("expect not inside work tree")
	}
	if check.Status != "needs_sync" {
		t.Fatalf("expect needs_sync, got %s", check.Status)
	}
	if check.Action != "clone" {
		t.Fatalf("expect clone action, got %s", check.Action)
	}
	if !filepath.IsAbs(check.RepoPath) {
		t.Fatalf("expect absolute repo path, got %q", check.RepoPath)
	}
}

func TestEnsureSubscribeRepoSyncSkipsRootAndTriggersClone(t *testing.T) {
	temp := t.TempDir()
	restoreWD := withWorkingDir(t, temp)
	defer restoreWD()

	var commands []string
	restoreGit := withGitRunner(t, func(_ string, args ...string) (string, error) {
		commands = append(commands, fmt.Sprintf("%s %q", args[0], args[1:]))
		switch {
		case args[0] == "rev-parse" && args[1] == "--is-inside-work-tree":
			return "true", nil
		case args[0] == "rev-parse" && args[1] == "--show-toplevel":
			return filepath.Dir(temp), nil
		case args[0] == "rev-parse" && args[1] == "--show-superproject-working-tree":
			return "", nil
		case args[0] == "rev-parse" && args[1] == "--git-dir":
			return ".git", nil
		case args[0] == "clone":
			return "", nil
		case args[0] == "fetch":
			return "", nil
		case args[0] == "reset":
			return "", nil
		}
		return "", nil
	})
	defer restoreGit()

	cfg := normalizeRepoDefaults(ServerConfig{})
	cfg.SubscribeRepoPath = filepath.Join(temp, "not-root")
	cfg.SubscribeRepoURL = "https://example.com/example.git"

	nonRootCheck, nonRootCtx, err := ensureSubscribeRepoSync(cfg)
	if err != nil {
		t.Fatalf("ensure repo sync should not fail: %v", err)
	}
	if nonRootCheck.Action != "clone_or_pull" {
		t.Fatalf("expect clone_or_pull action, got %s", nonRootCheck.Action)
	}
	if nonRootCheck.Status != "synced" {
		t.Fatalf("expect synced status, got %s", nonRootCheck.Status)
	}
	found := false
	for _, c := range commands {
		if strings.Contains(c, "clone") &&
			strings.Contains(c, "https://example.com/example.git") &&
			strings.Contains(c, "not-root") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected clone command, got %v", commands)
	}
	if nonRootCtx.IsRootRepository {
		t.Fatalf("expect non-root worktree, got root")
	}
}

func TestSyncRepoByFetchAndClone(t *testing.T) {
	temp := t.TempDir()
	repoPath := filepath.Join(temp, "repo")
	restoreWD := withWorkingDir(t, temp)
	defer restoreWD()

	var calls []string
	restoreGit := withGitRunner(t, func(_ string, args ...string) (string, error) {
		calls = append(calls, args[0]+" "+strings.Join(args[1:], " "))
		switch args[0] {
		case "fetch":
			return "", nil
		case "reset":
			return "", nil
		case "clone":
			return "", nil
		}
		return "", nil
	})
	defer restoreGit()

	if err := syncRepo(GitContext{}, normalizeRepoDefaults(ServerConfig{}), repoPath); err != nil {
		t.Fatalf("sync clone failed: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected one clone command, got %v", calls)
	}

	if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git failed: %v", err)
	}
	calls = nil
	if err := syncRepo(GitContext{}, normalizeRepoDefaults(ServerConfig{}), repoPath); err != nil {
		t.Fatalf("sync fetch/reset failed: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected fetch + reset, got %v", calls)
	}
}
