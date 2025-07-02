package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"

	objstore "github.com/ahrav/go-gitpack"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
	gitCmd.Flags().Bool("use-packfiles", false, "Use packfile parsing instead of git commands (faster for large repos)")
	gitCmd.Flags().Int("max-delta-depth", 100, "Maximum delta chain depth for packfile parsing")
	gitCmd.Flags().Bool("verify-crc", false, "Enable CRC verification for packfile parsing")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	logOpts := mustGetStringFlag(cmd, "log-opts")
	staged := mustGetBoolFlag(cmd, "staged")
	preCommit := mustGetBoolFlag(cmd, "pre-commit")
	usePackfiles := mustGetBoolFlag(cmd, "use-packfiles")
	maxDeltaDepth := mustGetIntFlag(cmd, "max-delta-depth")
	verifyCRC := mustGetBoolFlag(cmd, "verify-crc")

	var (
		findings []report.Finding
		err      error
		sourceO  sources.Source
	)

	if usePackfiles {
		var (
			packSource  *sources.GitPackfile
			scmPlatform scm.Platform
		)
		scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform"))
		if err != nil {
			logging.Fatal().Err(err).Send()
		}
		remote := sources.NewRemoteInfo(scmPlatform, source)

		packSource, err = sources.NewGitPackfile(source, &cfg, remote, detector.Sema)
		if err != nil {
			if errors.Is(err, objstore.ErrCommitGraphRequired) {
				logging.Warn().Msg("commit graph required for packfile parsing, falling back to git command approach")
			} else {
				logging.Error().Err(err).Msg("failed to create packfile source, falling back to git command approach")
			}
		} else {
			packSource.SetMaxDeltaDepth(maxDeltaDepth)
			packSource.SetVerifyCRC(verifyCRC)
			sourceO = packSource
		}
	}

	// Fallback if packfile scanning is disabled or failed
	if sourceO == nil {
		var (
			gitCmd      *sources.GitCmd
			scmPlatform scm.Platform
		)
		if preCommit || staged {
			if gitCmd, err = sources.NewGitDiffCmd(source, staged); err != nil {
				logging.Fatal().Err(err).Msg("could not create Git diff cmd")
			}
			// Remote info + links are irrelevant for staged changes.
			scmPlatform = scm.NoPlatform
		} else {
			if gitCmd, err = sources.NewGitLogCmd(source, logOpts); err != nil {
				logging.Fatal().Err(err).Msg("could not create Git log cmd")
			}
			if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
				logging.Fatal().Err(err).Send()
			}
		}
		sourceO = &sources.Git{
			Cmd:             gitCmd,
			Config:          &detector.Config,
			Remote:          sources.NewRemoteInfo(scmPlatform, source),
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		}
	}

	findings, err = detector.DetectSource(
		context.Background(),
		sourceO,
	)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
