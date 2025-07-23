// sources/git_packfile.go
package sources

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/semgroup"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"

	objstore "github.com/ahrav/go-gitpack"
)

var builderPool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate with a reasonable default capacity
		// Adjust based on your typical hunk size
		b := &strings.Builder{}
		b.Grow(1024) // 1KB default
		return b
	},
}

// lazyCommitInfo implements CommitInfoProvider for a specific commit
type lazyCommitInfo struct {
	commitHash objstore.Hash
	scanner    *objstore.HistoryScanner
	cache      *sync.Map
	remote     *RemoteInfo
}

func (l *lazyCommitInfo) GetCommitInfo() *CommitInfo {
	// Check cache first
	if cached, ok := l.cache.Load(l.commitHash); ok {
		return cached.(*CommitInfo)
	}

	// Fetch metadata
	meta, err := l.scanner.GetCommitMetadata(l.commitHash)
	if err != nil {
		logging.Debug().Err(err).Msgf("failed to get commit metadata for %x", l.commitHash)
		return nil
	}

	info := &CommitInfo{
		SHA:         l.commitHash.String(),
		Remote:      l.remote,
		AuthorName:  meta.Author.Name,
		AuthorEmail: meta.Author.Email,
		Date:        time.Unix(meta.Timestamp, 0).UTC().Format(time.RFC3339),
		// Note: Message would need to be parsed from the full commit object if needed
	}

	// Cache for future use
	l.cache.Store(l.commitHash, info)
	return info
}

// GitPackfile is a source that uses packfile parsing instead of git commands
type GitPackfile struct {
	RepoPath        string
	Config          *config.Config
	Remote          *RemoteInfo
	Sema            *semgroup.Group
	MaxArchiveDepth int

	scanner     *objstore.HistoryScanner
	commitCache *sync.Map
}

// NewGitPackfile creates a new GitPackfile source
func NewGitPackfile(repoPath string, cfg *config.Config, remote *RemoteInfo, sema *semgroup.Group) (*GitPackfile, error) {
	gitDir := repoPath
	if !strings.HasSuffix(gitDir, ".git") {
		gitDir = filepath.Join(repoPath, ".git")
	}

	scanner, err := objstore.NewHistoryScanner(gitDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create history scanner: %w", err)
	}

	return &GitPackfile{
		RepoPath:    repoPath,
		Config:      cfg,
		Remote:      remote,
		Sema:        sema,
		scanner:     scanner,
		commitCache: &sync.Map{},
	}, nil
}

// Fragments yields fragments from the git repo using packfile parsing
func (s *GitPackfile) Fragments(ctx context.Context, yield FragmentsFunc) error {
	defer s.scanner.Close()

	// Check if commit is allowed
	isCommitAllowed := func(sha string) bool {
		for _, a := range s.Config.Allowlists {
			if ok, _ := a.CommitAllowed(sha); ok {
				return true
			}
		}
		return false
	}

	// Stream hunks from the scanner
	hunks, errors := s.scanner.DiffHistoryHunks()

	// Debug counters
	hunkCount := 0
	fragmentCount := 0
	totalLines := 0

	// WaitGroup to coordinate with semaphore goroutines (like git.go)
	var wg sync.WaitGroup

	// Process hunks until channel closes or error received (like working standalone example)
	for {
		select {
		case hunk, ok := <-hunks:
			if !ok {
				// Hunks channel closed, we're done
				wg.Wait()
				logging.Debug().Msgf("Packfile scan complete: %d hunks -> %d fragments, %d total lines", hunkCount, fragmentCount, totalLines)
				return nil
			}

			hunkCount++
			commitSHA := hunk.Commit().String()

			// Skip if commit is in allowlist
			if isCommitAllowed(commitSHA) {
				logging.Trace().Str("allowed-commit", commitSHA).Msg("skipping commit: global allowlist")
				continue
			}

			// Skip archive files
			if isArchive(ctx, hunk.Path()) {
				logging.Debug().Str("path", hunk.Path()).Msg("skipping archive file in packfile scan")
				continue
			}

			fragmentCount++
			lines := hunk.Lines()
			totalLines += len(lines)

			// Skip very large hunks (likely generated files, minified code, etc.)
			maxLines := 1_000
			if len(lines) > maxLines {
				logging.Debug().Msgf("Skipping large hunk: commit=%s, path=%s, lines=%d (max=%d)",
					commitSHA[:8], hunk.Path(), len(lines), maxLines)
				continue
			}

			// Debug: Log first few hunks to see what we're processing
			if hunkCount <= 5 {
				logging.Debug().Msgf("Hunk %d: commit=%s, path=%s, lines=%d, start=%d",
					hunkCount, commitSHA[:8], hunk.Path(), len(lines), hunk.StartLine())
			}

			// Process hunk with proper semaphore coordination (like git.go)
			wg.Add(1)
			s.Sema.Go(func() error {
				defer wg.Done()

				rawBuilder := builderPool.Get().(*strings.Builder)
				defer builderPool.Put(rawBuilder)
				rawBuilder.Reset()

				for _, line := range lines {
					rawBuilder.WriteString(line)
					rawBuilder.WriteString("\n")
				}

				fragment := Fragment{
					CommitSHA: commitSHA,
					FilePath:  hunk.Path(),
					Raw:       rawBuilder.String(),
					StartLine: hunk.StartLine(),
				}

				// Set the lazy loader
				fragment.SetCommitInfoProvider(&lazyCommitInfo{
					commitHash: hunk.Commit(),
					scanner:    s.scanner,
					cache:      s.commitCache,
					remote:     s.Remote,
				})

				// Yield fragment (like git.go)
				if err := yield(fragment, nil); err != nil {
					return err
				}

				return nil
			})

		case err := <-errors:
			// Any error (including nil) means we're done (like working standalone example)
			if err != nil && err != objstore.ErrCommitGraphRequired {
				logging.Error().Err(err).Msg("error during packfile scanning")
				wg.Wait()
				return err
			}
			wg.Wait()
			logging.Debug().Msgf("Packfile scan complete: %d hunks -> %d fragments, %d total lines", hunkCount, fragmentCount, totalLines)
			return nil
		}
	}
}

// Close closes the underlying scanner
func (s *GitPackfile) Close() error {
	if s.scanner != nil {
		return s.scanner.Close()
	}
	return nil
}

// SetMaxDeltaDepth configures the maximum delta chain depth for object retrieval
func (s *GitPackfile) SetMaxDeltaDepth(depth int) {
	// Note: SetMaxDeltaDepth may not be available in current go-gitpack version
	// This is a placeholder for when the method becomes available
}

// SetVerifyCRC enables or disables CRC-32 validation
func (s *GitPackfile) SetVerifyCRC(verify bool) {
	// Note: SetVerifyCRC may not be available in current go-gitpack version
	// This is a placeholder for when the method becomes available
}
