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
	scanner.SetMaxDeltaDepth(100)

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

	// Process errors in background
	errDone := make(chan struct{})
	go func() {
		defer close(errDone)
		if err := <-errors; err != nil && err != objstore.ErrCommitGraphRequired {
			logging.Error().Err(err).Msg("error during packfile scanning")
		}
	}()

	// Process hunks with concurrency control
	var wg sync.WaitGroup

	for hunk := range hunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		commitSHA := hunk.Commit().String()

		// Skip if commit is in allowlist
		if isCommitAllowed(commitSHA) {
			logging.Trace().Str("allowed-commit", commitSHA).Msg("skipping commit: global allowlist")
			continue
		}

		wg.Add(1)
		s.Sema.Go(func() error {
			defer wg.Done()

			// Check if this is an archive file
			if isArchive(ctx, hunk.Path()) {
				// For archives, we need to get the blob content
				// This would require extending your scanner to provide blob access
				// For now, we'll skip archives
				logging.Debug().Str("path", hunk.Path()).Msg("skipping archive file in packfile scan")
				return nil
			}

			// Combine hunk lines into raw content
			rawBuilder := builderPool.Get().(*strings.Builder)
			defer builderPool.Put(rawBuilder)
			rawBuilder.Reset()

			for _, line := range hunk.Lines() {
				rawBuilder.Write(line)
				rawBuilder.WriteByte('\n')
			}

			fragment := Fragment{
				CommitSHA: commitSHA,
				FilePath:  hunk.Path(),
				Raw:       rawBuilder.String(),
				StartLine: hunk.StartLine(),
				// Don't set CommitInfo - use lazy loading instead
			}

			// Set the lazy loader
			fragment.SetCommitInfoProvider(&lazyCommitInfo{
				commitHash: hunk.Commit(),
				scanner:    s.scanner,
				cache:      s.commitCache,
				remote:     s.Remote,
			})

			return yield(fragment, nil)
		})
	}

	wg.Wait()
	<-errDone
	return nil
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
	if s.scanner != nil {
		s.scanner.SetMaxDeltaDepth(depth)
	}
}

// SetVerifyCRC enables or disables CRC-32 validation
func (s *GitPackfile) SetVerifyCRC(verify bool) {
	if s.scanner != nil {
		s.scanner.SetVerifyCRC(verify)
	}
}
