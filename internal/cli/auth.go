package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/state"
)

func authCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Manage server credentials"}

	var server, token string
	login := &cobra.Command{
		Use:   "login",
		Short: "Log in with a device token created in the WebUI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := state.LoadConfig()
			if err != nil {
				return err
			}
			in := bufio.NewReader(os.Stdin)
			if server == "" {
				if server, err = prompt(in, "Server URL", cfg.Server); err != nil {
					return err
				}
			}
			if token == "" {
				if token, err = promptSecret(in, "Token"); err != nil {
					return err
				}
			}
			server = strings.TrimRight(strings.TrimSpace(server), "/")
			token = strings.TrimSpace(token)
			if server == "" || token == "" {
				return errors.New("server and token are required")
			}
			who, err := client.New(server, token).WhoAmI()
			if err != nil {
				return err
			}
			cfg.Server, cfg.Token, cfg.Device = server, token, who.Device
			if err := state.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("Logged in to %s as device %q\n", server, who.Device)
			return nil
		},
	}
	login.Flags().StringVar(&server, "server", "", "server URL")
	login.Flags().StringVar(&token, "token", "", "device token")

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
