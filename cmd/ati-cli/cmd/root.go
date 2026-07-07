package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Run builds and executes the root command, returning any error.
func Run() error {
	rootCmd := buildRootCmd()
	return rootCmd.Execute()
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ati-cli",
		Short: "ATI CLI - Agent Transparency Infrastructure Command Line Tool",
		Long: `A command-line tool for interacting with the Agent Transparency Infrastructure (ATI).
Use this tool to register agents, verify domain ownership, and search for registered agents.`,
	}

	cobra.OnInitialize(initConfig)

	// Global flags
	cmd.PersistentFlags().String("api-key", "", "API key for authentication (env: ATI_API_KEY)")
	cmd.PersistentFlags().String("base-url", "https://ra.ansagent.cn:8180/ans/api/v1", "API base URL (env: ATI_BASE_URL)")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	cmd.PersistentFlags().BoolP("json", "j", false, "Output in JSON format")

	// Bind flags to viper
	_ = viper.BindPFlag("api-key", cmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("base-url", cmd.PersistentFlags().Lookup("base-url"))
	_ = viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("json", cmd.PersistentFlags().Lookup("json"))

	// Add all subcommands
	cmd.AddCommand(
		buildBadgeCmd(),
		buildCsrStatusCmd(),
		buildEventsCmd(),
		buildGenerateCSRCmd(),
		buildGetIdentityCertsCmd(),
		buildGetServerCertsCmd(),
		buildRegisterCmd(),
		buildResolveCmd(),
		buildRevokeCmd(),
		buildSearchCmd(),
		buildStatusCmd(),
		buildSubmitIdentityCSRCmd(),
		buildSubmitServerCSRCmd(),
		buildVerifyACMECmd(),
		buildVerifyDNSCmd(),
	)

	return cmd
}

func initConfig() {
	// Environment variable support
	viper.SetEnvPrefix("ATI")

	// Explicitly bind environment variables (handles hyphenated flag names)
	_ = viper.BindEnv("api-key", "ATI_API_KEY")
	_ = viper.BindEnv("base-url", "ATI_BASE_URL")

	viper.AutomaticEnv()
}
