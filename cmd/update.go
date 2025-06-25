package cmd

import (
	"log"
	"os"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spf13/cobra"
)

var (
	profile           string
	once              bool
	retryUpdateErrors bool
)

func init() {
	initCredentialsSubCommand(updateCmd)
	updateCmd.PersistentFlags().StringVar(&profile, "profile", "default", "profile to update")
	updateCmd.PersistentFlags().BoolVar(&once, "once", false, "to update the profile just once")
	updateCmd.PersistentFlags().BoolVar(&retryUpdateErrors, "retry-errors", false, "Retry indefinitely on errors with a backoff time. Useful for unattended background processes")
}

var updateCmd = &cobra.Command{
	Use:   "update [flags]",
	Short: "Updates a profile in the AWS credentials file with new AWS credentials",
	Long:  "Updates a profile in the AWS credentials file with new AWS credentials",
	Run: func(cmd *cobra.Command, args []string) {
		if once && retryUpdateErrors {
			log.Fatal("Cannot use both --once and --retry-errors flags together")
		}

		err := PopulateCredentialsOptions()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		helper.Debug = credentialsOptions.Debug

		opts := helper.UpdateOpts{
			Profile: profile,
		}

		if once {
			opts.Mode = helper.UpdateOnceMode
		} else if retryUpdateErrors {
			opts.Mode = helper.UpdateRetryMode
		} else {
			// Default to fail-fast: update before creds expiration but exit on errors
			opts.Mode = helper.UpdateFailFastMode
		}

		helper.Update(credentialsOptions, opts)
	},
}
