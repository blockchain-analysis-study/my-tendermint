package main

import (
	"os"
	"path/filepath"

	"my-tendermint/tendermint/libs/cli"

	cmd "my-tendermint/tendermint/cmd/tendermint/commands"
	cfg "my-tendermint/tendermint/config"
	nm "my-tendermint/tendermint/node"
)


/**
创建 tendermint 节点
 */
func main() {
	rootCmd := cmd.RootCmd
	rootCmd.AddCommand(
		cmd.GenValidatorCmd,
		cmd.InitFilesCmd,
		cmd.ProbeUpnpCmd,
		cmd.LiteCmd,
		cmd.ReplayCmd,
		cmd.ReplayConsoleCmd,
		cmd.ResetAllCmd,
		cmd.ResetPrivValidatorCmd,
		cmd.ShowValidatorCmd,
		cmd.TestnetFilesCmd,
		cmd.ShowNodeIDCmd,
		cmd.GenNodeKeyCmd,
		cmd.VersionCmd)

	// NOTE:
	// Users wishing to:
	//	* Use an external signer for their validators
	//	* Supply an in-proc abci app
	//	* Supply a genesis doc file from another source
	//	* Provide their own DB implementation
	// can copy this file and use something other than the
	// DefaultNewNode function
	/**
	TODO 创建一个 tendermint  节点实例
	这是一个 func
	 */
	nodeFunc := nm.DefaultNewNode

	// Create & start node
	/**
	TODO  将 启动节点的func 注册到rootCmd
	 */
	rootCmd.AddCommand(cmd.NewRunNodeCmd(nodeFunc))

	cmd := cli.PrepareBaseCmd(rootCmd, "TM", os.ExpandEnv(filepath.Join("$HOME", cfg.DefaultTendermintDir)))
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
