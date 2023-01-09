package cmd

import (
	"github.com/spf13/cobra"
	"log"
	"syscall"
)

var rootCmd = &cobra.Command{
	Use:   "aws_signing_helper [command]",
	Short: "The credential helper is a tool to retrieve temporary AWS credentials",
	Long: `A tool that utilizes certificates and their associated private keys to 
sign requests to AWS IAM Roles Anywhere's CreateSession API and retrieve temporary 
AWS security credentials. This tool exposes multiple commands to make credential 
retrieval and rotation more convenient.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		syscall.Exit(1)
	}
}
