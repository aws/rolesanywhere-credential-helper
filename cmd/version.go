package cmd

import (
    "fmt"

	"github.com/spf13/cobra"
)

var (
    Version string
)    

func init() {
    rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version number of the credential helper",
	Long:  "Prints the version number of the credential helper",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}
