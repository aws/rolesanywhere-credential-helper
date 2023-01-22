package cmd

import (
	"log"
	"syscall"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	profile string
	once    bool
)

func init() {
	initCredentialsSubCommand(updateCmd)
	updateCmd.PersistentFlags().StringVar(&profile, "profile", "default", "profile to update")
	updateCmd.PersistentFlags().BoolVar(&once, "once", false, "to update the profile just once")
}

var updateCmd = &cobra.Command{
	Use:   "update [flags]",
	Short: "Updates a profile in the AWS credentials file with new AWS credentials",
	Long:  "Updates a profile in the AWS credentials file with new AWS credentials",
	Run: func(cmd *cobra.Command, args []string) {
		err := PopulateCredentialsOptions()
		if err != nil {
			log.Println(err)
			syscall.Exit(1)
		}
		helper.Update(credentialsOptions, profile, once)
	},
}
