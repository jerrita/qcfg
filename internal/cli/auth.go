package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/state"
)

const defaultServer = "https://ctrl.jerrita.cn"

func authCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Manage server credentials"}

	var name, token string
	login := &cobra.Command{
		Use:   "login",
		Short: "Log in by approving this device in the WebUI, or with a token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := state.LoadConfig()
			if err != nil {
				return err
			}
			server := strings.TrimSpace(cfg.Server)
			if server == "" {
				server = defaultServer
			}
			server = strings.TrimRight(server, "/")
			if server == "" {
				return errors.New("server is required")
			}
			if token != "" {
				if name != "" {
					return errors.New("--name cannot be used with --token")
				}
				c := client.New(server, strings.TrimSpace(token))
				who, err := c.WhoAmI()
				if err != nil {
					return fmt.Errorf("token login failed: %w", err)
				}
				cfg.Server, cfg.Token, cfg.Device = server, strings.TrimSpace(token), who.Device
				if err := state.SaveConfig(cfg); err != nil {
					return err
				}
				fmt.Printf("Logged in to %s as %q\n", server, who.Device)
				return nil
			}
			if name == "" {
				if name, err = os.Hostname(); err != nil {
					return err
				}
			}
			c := client.New(server, "")
			dc, err := c.DeviceCode(name)
			if err != nil {
				return err
			}
			fmt.Printf("Open %s/activate and enter code: %s\nWaiting for approval...\n", server, dc.UserCode)
			for {
				time.Sleep(time.Duration(dc.Interval) * time.Second)
				tok, err := c.DeviceToken(dc.DeviceCode)
				switch {
				case errors.Is(err, client.ErrAuthPending):
					continue
				case errors.Is(err, client.ErrAuthDenied):
					return errors.New("login request denied")
				case errors.Is(err, client.ErrAuthExpired):
					return errors.New("code expired, run `qcfg auth login` again")
				case err != nil:
					return err
				}
				cfg.Server, cfg.Token, cfg.Device = server, tok.Token, tok.Device
				if err := state.SaveConfig(cfg); err != nil {
					return err
				}
				fmt.Printf("Logged in to %s as device %q\n", server, tok.Device)
				return nil
			}
		},
	}
	login.Flags().StringVar(&name, "name", "", "device name (default: hostname)")
	login.Flags().StringVar(&token, "token", "", "access token created in the WebUI (skips device approval)")

	logout := &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := state.LoadConfig()
			if err != nil {
				return err
			}
			cfg.Token = ""
			return state.SaveConfig(cfg)
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show login status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, c, err := session()
			if err != nil {
				return err
			}
			who, err := c.WhoAmI()
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(map[string]string{"server": cfg.Server, "device": who.Device})
			}
			fmt.Printf("Server: %s\nDevice: %s\n", cfg.Server, who.Device)
			return nil
		},
	}

	cmd.AddCommand(login, logout, status)
	return cmd
}

func prompt(in *bufio.Reader, label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if line = strings.TrimSpace(line); line == "" {
		return def, nil
	}
	return line, nil
}

func promptSecret(in *bufio.Reader, label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return prompt(in, label, "")
	}
	fmt.Printf("%s: ", label)
	b, err := term.ReadPassword(fd)
	fmt.Println()
	return string(b), err
}
