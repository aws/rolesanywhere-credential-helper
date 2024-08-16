package cmd

import (
	"log"
	"os"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	port     int
	hopLimit int
)

func init() {
	initCredentialsSubCommand(serveCmd)
	serveCmd.PersistentFlags().IntVar(&port, "port", helper.DefaultPort, "The port used to run the local server")
	serveCmd.PersistentFlags().IntVar(&hopLimit, "hop-limit", helper.DefaultHopLimit, "The IP TTL to set on responses")
}

var serveCmd = &cobra.Command{
	Use:   "serve [flags]",
	Short: "Serve AWS credentials through a local endpoint",
	Long:  "Serve AWS credentials through a local endpoint that is compatible with IMDSv2",
	Run: func(cmd *cobra.Command, args []string) {
		err := PopulateCredentialsOptions()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		helper.Debug = credentialsOptions.Debug
		credentialsOptions.ServerTTL = hopLimit

		helper.Serve(port, credentialsOptions)
	},
}
