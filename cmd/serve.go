package cmd

import (
	"log"
	"os"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	port int
)

func init() {
	initCredentialsSubCommand(serveCmd)
	serveCmd.PersistentFlags().IntVar(&port, "port", helper.DefaultPort, "The port used to run the local server (default: 9911)")
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
		helper.Serve(port, credentialsOptions)
	},
}
