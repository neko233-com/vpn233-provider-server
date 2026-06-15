package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultSubscribeRepoURL  = "https://github.com/neko233-com/vpn233-subscribe-server.git"
	defaultSubscribeRepoDir  = "vpn233-subscribe-server"
	defaultSubscribeRepoMain = "main"
)

type GitContext struct {
	InsideWorkTree   bool   `json:"inside_work_tree"`
	IsSubmodule      bool   `json:"is_submodule"`
	TopLevel         string `json:"top_level"`
	GitDir           string `json:"git_dir"`
	SubprojectTopLvl  string `json:"superproject_top_level"`
	IsRootRepository bool   `json:"is_root_repository"`
}

type RepoCheckResult struct {
	RequestedPath string `json:"requested_path"`
	RepoPath      string `json:"repo_path"`
	RepoURL       string `json:"repo_url"`
	Branch        string `json:"branch"`
	Action        string `json:"action"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

type RepoSyncConfig struct {
	WorkspaceRoot string
	RepoURL      string
	RepoDir      string
	Branch       string
	Now          func() time.Time
}

type gitRunner func(dir string, args ...string) (string, error)

var runGitCommand gitRunner = runGitCommandDefault

func runGitCommandDefault(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func inspectGitContext(dir string) (GitContext, error) {
	cleanDir, err := filepath.Abs(dir)
	if err != nil {
		return GitContext{}, err
	}

	out, err := runGitCommand(cleanDir, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(out) != "true" {
		return GitContext{InsideWorkTree: false}, nil
	}

	top, err := runGitCommand(cleanDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return GitContext{}, err
	}
	sub, _ := runGitCommand(cleanDir, "rev-parse", "--show-superproject-working-tree")
	gitDir, _ := runGitCommand(cleanDir, "rev-parse", "--git-dir")
	cleanTop := filepath.Clean(top)
	return GitContext{
		InsideWorkTree:   true,
		TopLevel:         top,
		IsSubmodule:      sub != "",
		GitDir:           gitDir,
		SubprojectTopLvl: sub,
		IsRootRepository: strings.EqualFold(cleanTop, filepath.Clean(cleanDir)),
	}, nil
}

func repoSyncOptionFromConfig(cfg ServerConfig) RepoSyncConfig {
	return RepoSyncConfig{
		WorkspaceRoot: "",
		RepoURL:      cfg.SubscribeRepoURL,
		RepoDir:      cfg.SubscribeRepoPath,
		Branch:       cfg.SubscribeRepoBranch,
		Now:          time.Now,
	}
}

func ensureSubscribeRepoSync(cfg ServerConfig) (RepoCheckResult, GitContext, error) {
	check, ctx, err := inspectRepoState(cfg)
	if err != nil {
		return check, ctx, err
	}
	if ctx.IsSubmodule {
		return check, ctx, nil
	}
	if ctx.InsideWorkTree && ctx.IsRootRepository {
		return check, ctx, nil
	}
	if err := syncRepo(ctx, cfg, check.RepoPath); err != nil {
		check.Status = "failed"
		check.Error = err.Error()
		return check, ctx, err
	}
	check.Status = "synced"
	check.Action = "clone_or_pull"
	return check, ctx, nil
}

func inspectRepoState(cfg ServerConfig) (RepoCheckResult, GitContext, error) {
	check := RepoCheckResult{
		RepoURL: cfg.SubscribeRepoURL,
		Branch:  cfg.SubscribeRepoBranch,
	}
	if cfg.SubscribeRepoURL == "" {
		return check, GitContext{InsideWorkTree: false}, fmt.Errorf("empty subscribe repo url")
	}
	if cfg.SubscribeRepoPath == "" {
		cfg.SubscribeRepoPath = defaultSubscribeRepoDir
	}
	check.RepoPath = cfg.SubscribeRepoPath

	workDir, _ := os.Getwd()
	check.RequestedPath = workDir
	if cleanRepoPath := filepath.Clean(cfg.SubscribeRepoPath); !filepath.IsAbs(cleanRepoPath) {
		check.RepoPath = filepath.Join(workDir, cleanRepoPath)
	}

	ctx, err := inspectGitContext(workDir)
	if err != nil {
		return check, ctx, err
	}
	if ctx.InsideWorkTree && !ctx.IsSubmodule && ctx.IsRootRepository {
		check.Status = "skip_root_git"
		check.Action = "skip"
		return check, ctx, nil
	}
	if !ctx.InsideWorkTree {
		check.Status = "needs_sync"
		check.Action = "clone"
	} else if ctx.IsSubmodule {
		check.Status = "submodule"
		check.Action = "skip"
	} else {
		check.Status = "needs_sync"
		check.Action = "clone_or_pull"
	}
	return check, ctx, nil
}

func syncRepo(ctx GitContext, cfg ServerConfig, repoPath string) error {
	workDir := filepath.Dir(repoPath)
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		if ctx.IsSubmodule {
			return nil
		}
		_, err = runGitCommand(repoPath, "fetch", "origin", cfg.SubscribeRepoBranch)
		if err != nil {
			return err
		}
		_, err = runGitCommand(repoPath, "reset", "--hard", "origin/"+cfg.SubscribeRepoBranch)
		return err
	}

	_, err := runGitCommand(workDir, "clone", "--depth", "1", "-b", cfg.SubscribeRepoBranch, cfg.SubscribeRepoURL, filepath.Base(repoPath))
	return err
}

func normalizeRepoDefaults(cfg ServerConfig) ServerConfig {
	out := cfg
	if out.SubscribeRepoURL == "" {
		out.SubscribeRepoURL = defaultSubscribeRepoURL
	}
	if out.SubscribeRepoPath == "" {
		out.SubscribeRepoPath = defaultSubscribeRepoDir
	}
	if out.SubscribeRepoBranch == "" {
		out.SubscribeRepoBranch = defaultSubscribeRepoMain
	}
	return out
}
