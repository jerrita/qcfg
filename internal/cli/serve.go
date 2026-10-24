package cli

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
	"github.com/jerrita/qcfg/internal/web"
)

func openStore(dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	key, err := crypto.LoadOrCreateKey(dataDir)
	if err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dataDir, "qcfg.db"), key)
}

func serveCmd() *cobra.Command {
	var listen, dataDir, certFile, keyFile string
	var maxSize int64
	var keep int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the qcfg server and WebUI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (certFile == "") != (keyFile == "") {
				return errors.New("--tls-cert and --tls-key must be set together")
			}
			st, err := openStore(dataDir)
			if err != nil {
				return err
			}
			defer st.Close()
			st.KeepVersions = keep

			if _, err := st.Setting(web.PasswordKey); errors.Is(err, store.ErrNotFound) {
				pw := crypto.RandomString(12)
				if err := st.SetSetting(web.PasswordKey, crypto.HashPassword(pw)); err != nil {
					return err
				}
				log.Printf("generated WebUI admin password: %s (change with `qcfg serve passwd`)", pw)
			} else if err != nil {
				return err
			}

			h := server.New(st, server.Options{MaxFileSize: maxSize}, web.New(st, web.Options{
				MaxFileSize: maxSize,
				SecureOnly:  certFile != "",
			}))
			srv := &http.Server{
				Addr:              listen,
				Handler:           h,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       2 * time.Minute,
				WriteTimeout:      2 * time.Minute,
				IdleTimeout:       2 * time.Minute,
			}
			log.Printf("qcfg listening on %s (data: %s)", listen, dataDir)
			if certFile != "" {
				return srv.ListenAndServeTLS(certFile, keyFile)
			}
			return srv.ListenAndServe()
		},
	}
	cmd.PersistentFlags().StringVar(&dataDir, "data", "./data", "data directory")
	cmd.Flags().StringVar(&listen, "listen", ":8080", "listen address")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "TLS certificate file")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "TLS key file")
	cmd.Flags().Int64Var(&maxSize, "max-file-size", 4<<20, "max file size in bytes")
	cmd.Flags().IntVar(&keep, "keep-versions", 50, "versions kept per file, 0 keeps all")

	passwd := &cobra.Command{
		Use:   "passwd",
		Short: "Set the WebUI admin password",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openStore(dataDir)
			if err != nil {
				return err
			}
			defer st.Close()
			in := bufio.NewReader(os.Stdin)
			pw, err := promptSecret(in, "New password")
			if err != nil {
				return err
			}
			again, err := promptSecret(in, "Repeat password")
			if err != nil {
				return err
			}
			if pw != again {
				return errors.New("passwords do not match")
			}
			if len(pw) < 8 {
				return errors.New("password must be at least 8 characters")
			}
			if err := st.SetSetting(web.PasswordKey, crypto.HashPassword(pw)); err != nil {
				return err
			}
			fmt.Println("password updated")
			return nil
		},
	}
	cmd.AddCommand(passwd)
	return cmd
}
