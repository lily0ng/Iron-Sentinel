package cli

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"iron-sentinel/core/internal/serverapp"
)

func NewServerCmd() *cobra.Command {
	var port int
	var tlsEnabled bool
	var tlsCert string
	var tlsKey string
	var dataDir string
	var psk string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run centralized command server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dataDir == "" {
				dataDir = "./server-data"
			}

			srv := serverapp.New(serverapp.Config{DataDir: dataDir, PSK: psk})
			_ = srv.LoadFromDisk()

			h := srv.Handler()
			httpSrv := &http.Server{
				Addr:              fmt.Sprintf(":%d", port),
				Handler:           h,
				ReadHeaderTimeout: 10 * time.Second,
			}

			if tlsEnabled {
				if tlsCert == "" || tlsKey == "" {
					return fmt.Errorf("--tls-cert and --tls-key are required when --tls-enabled=true")
				}
				fmt.Printf("server listening https://0.0.0.0:%d (data-dir=%s)\n", port, dataDir)
				return httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
			}

			fmt.Printf("server listening http://0.0.0.0:%d (data-dir=%s)\n", port, dataDir)
			return httpSrv.ListenAndServe()
		},
	}

	cmd.Flags().IntVar(&port, "port", 8443, "Server port")
	cmd.Flags().BoolVar(&tlsEnabled, "tls-enabled", true, "Enable TLS")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate (PEM)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key (PEM)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "./server-data", "Server data directory")
	cmd.Flags().StringVar(&psk, "psk", "", "Pre-shared key required for enroll/enqueue (X-PSK)")
	return cmd
}
