package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/ac0d3r/machbox/core/assets"
	"github.com/ac0d3r/machbox/core/logger"
	"github.com/ac0d3r/machbox/core/vm"
	"github.com/ac0d3r/machbox/core/vm/config"

	vz "github.com/Code-Hex/vz/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type logOptions struct {
	level  string
	output string
	JSON   bool
}

type vmOptions struct {
	vbvmPath    string
	display     string
	width       int64
	height      int64
	headless    bool
	networkMode string
}

var version = "dev"

type rootOptions struct {
	log logOptions
}

func NewRootCommand() *cobra.Command {
	opts := &rootOptions{}

	cmd := &cobra.Command{
		Use:           "machbox",
		Short:         "macOS malware analysis sandbox",
		Version:       version,
		SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := logger.Init(&logger.Config{
				Level:  opts.log.level,
				Output: opts.log.output,
				Format: opts.log.JSON}); err != nil {
				return err
			}
			return assets.Init()
		},
	}

	cmd.SetVersionTemplate("{{.Name}} version {{.Version}}\n")

	cmd.PersistentFlags().StringVar(&opts.log.level, "log-level",
		"info", "log level: debug, info, warn, error")
	cmd.PersistentFlags().StringVar(&opts.log.output, "log-output",
		"", "log file path, empty for stdout")
	cmd.PersistentFlags().BoolVar(&opts.log.JSON, "log-json",
		false, "enable JSON log output")

	cmd.AddCommand(
		newSetuptCommand(),
		newAnalyzeCommand(),
		newReportViewCommand(),
	)

	return cmd
}

// Execute creates the root command and runs it.
func Execute() error {
	return NewRootCommand().Execute()
}

func bindVMFlags(cmd *cobra.Command, opts *vmOptions) {
	opts.display = fmt.Sprintf("%dx%d", config.DefaultDisplayWidth, config.DefaultDisplayHeight)

	cmd.Flags().StringVar(&opts.display, "display",
		opts.display, "display resolution, e.g. 1920x1080")

	cmd.Flags().BoolVar(&opts.headless, "headless",
		true, "run without a GUI window")

	cmd.Flags().StringVar(
		&opts.networkMode,
		"network-mode",
		"",
		fmt.Sprintf("Network mode (%s)", strings.Join(config.NetworkModes, ", ")),
	)

	cmd.Flags().StringVarP(&opts.vbvmPath, "vbvm", "m",
		"", "path to VBVM virtual machine bundle")

	_ = cmd.MarkFlagRequired("vbvm")
}

func (opts *vmOptions) parseDisplay() error {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(opts.display)), "x")
	if len(parts) != 2 {
		return fmt.Errorf("invalid --display value %q, expected WxH", opts.display)
	}

	width, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return err
	}
	height, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return err
	}

	opts.width = width
	opts.height = height

	return nil
}

func (opts *vmOptions) parseNetwork() config.Network {
	opts.networkMode = strings.TrimSpace(opts.networkMode)
	for _, v := range config.NetworkModes {
		if strings.EqualFold(opts.networkMode, v) {
			return config.Network{Enable: true, Mode: opts.networkMode}
		}
	}

	return config.Network{Enable: false}
}

func safetyRunVM(ctx context.Context,
	opts *vmOptions,
	vmcfg *vz.VirtualMachineConfiguration,
	onVMStarted func(*vm.VMInstance)) error {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vmInstance, err := vm.New(ctx, vmcfg)
	if err != nil {
		return fmt.Errorf("failed to create VM instance: %w", err)
	}

	if err := vmInstance.Start(); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}
	logrus.Info("VM started successfully")

	if onVMStarted != nil {
		onVMStarted(vmInstance)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if !opts.headless {
		logrus.Infof("showing GUI window (%dx%d)", opts.width, opts.height)
		if err := vmInstance.ShowGraphic(opts.width, opts.height); err != nil {
			return fmt.Errorf("ShowGraphic error: %w", err)
		}
	}

	select {
	case <-vmInstance.AlreadyShutdown():
		if err := vmInstance.Shutdown(); err != nil {
			logrus.Errorf("failed to stop VM: %v", err)
		}
	case <-sigCh:
		if err := vmInstance.Shutdown(); err != nil {
			logrus.Errorf("failed to stop VM: %v", err)
		}
	}

	logrus.Info("VM fully stopped")
	return nil
}
