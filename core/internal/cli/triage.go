package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"iron-sentinel/core/internal/triage"
)

func NewTriageCmd() *cobra.Command {
	var output string
	var caseID string
	var iocFile string
	var snapshotPaths []string
	var snapshotMode string
	var snapshotHash bool
	var snapshotMaxFileBytes int64
	var snapshotMaxTotalBytes int64
	var snapshotMaxFiles int
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Collect rapid response triage artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if caseID == "" {
				caseID = uuid.NewString()
			}
			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

			res, err := triage.Run(ctx, triage.Options{
				CaseID:                caseID,
				Output:                output,
				IOCFile:               iocFile,
				SnapshotPaths:         snapshotPaths,
				SnapshotMode:          snapshotMode,
				SnapshotHashFiles:     snapshotHash,
				SnapshotMaxFileBytes:  snapshotMaxFileBytes,
				SnapshotMaxTotalBytes: snapshotMaxTotalBytes,
				SnapshotMaxFiles:      snapshotMaxFiles,
				StartedAt:             time.Now().UTC(),
			})
			if err != nil {
				return err
			}
			fmt.Printf("case=%s output=%s artifacts=%d\n", res.CaseID, res.OutputDir, len(res.Artifacts))
			return nil
		},
	}

	cmd.Flags().StringVar(&output, "output", "./evidence", "Evidence output directory")
	cmd.Flags().StringVar(&caseID, "case-id", "", "Case ID (default: random UUID)")
	cmd.Flags().StringVar(&iocFile, "ioc-file", "", "IOC list file (one pattern per line)")
	cmd.Flags().StringArrayVar(&snapshotPaths, "snapshot-path", nil, "Filesystem snapshot path (repeatable)")
	cmd.Flags().StringVar(&snapshotMode, "snapshot-mode", "metadata", "Snapshot mode (metadata|copy)")
	cmd.Flags().BoolVar(&snapshotHash, "snapshot-hash", false, "Hash regular files during snapshot (best-effort)")
	cmd.Flags().Int64Var(&snapshotMaxFileBytes, "snapshot-max-file-bytes", 25*1024*1024, "Max single file size to hash/copy")
	cmd.Flags().Int64Var(&snapshotMaxTotalBytes, "snapshot-max-total-bytes", 250*1024*1024, "Max total bytes to copy into tar.gz (copy mode)")
	cmd.Flags().IntVar(&snapshotMaxFiles, "snapshot-max-files", 20000, "Max number of filesystem entries to walk")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Overall triage timeout")
	return cmd
}
