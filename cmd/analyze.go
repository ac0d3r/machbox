package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/ac0d3r/machbox/core/assets"
	"github.com/ac0d3r/machbox/core/vm"
	"github.com/ac0d3r/machbox/core/vm/config"
	"github.com/ac0d3r/machbox/core/vsock"
	"github.com/ac0d3r/machbox/core/vsock/protocol"
	"github.com/ac0d3r/machbox/report"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type analyzeOption struct {
	vmOptions

	samplePath string
	sampleName string
	sampleArgs []string

	timeout  int
	password string

	workpath  string
	sharepath string
}

func (opts *analyzeOption) parseArgs(args []string) (err error) {
	samplePath := args[0]
	if !filepath.IsAbs(samplePath) {
		samplePath, err = filepath.Abs(samplePath)
		if err != nil {
			return err
		}
	}
	opts.samplePath = filepath.Clean(string(os.PathSeparator) + samplePath)
	opts.sampleName = filepath.Base(opts.samplePath)

	opts.sampleArgs = args[1:]
	if len(opts.sampleArgs) > 0 && opts.sampleArgs[0] == "--" {
		opts.sampleArgs = opts.sampleArgs[1:]
	}
	return nil
}

func (opts *analyzeOption) vmSamplePath() string {
	return filepath.Join(opts.sharepath, opts.sampleName)
}

func newAnalyzeCommand() *cobra.Command {
	opts := &analyzeOption{}

	cmd := &cobra.Command{
		Use:                   "analyze [flags] <sample> [--] [sample-args...]",
		Short:                 "Run malware analysis inside the sandbox VM",
		DisableFlagsInUseLine: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("missing sample file path")
			}
			if _, err := os.Stat(args[0]); err != nil {
				return fmt.Errorf("sample not found: %w", err)
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return report.InitDB()
		},
		PostRunE: func(cmd *cobra.Command, args []string) error {
			return report.CloseDB()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			if err := opts.parseArgs(args); err != nil {
				return err
			}

			// Create shared directory
			shared, err := assets.NewShareDir(opts.sampleName,
				opts.samplePath, "statictool", "dynamictool", "DTrace/network.d")
			if err != nil {
				return fmt.Errorf("prepare shared directory: %w", err)
			}
			logrus.Infof("creating shared directory at %s", shared.Path())
			defer func() {
				logrus.Info("cleaning up shared directory")
				if err := shared.Clean(); err != nil {
					logrus.Warnf("failed to remove shared directory: %v", err)
				}
			}()

			logrus.Infof("decoding VBVM path: %s", opts.vbvmPath)
			vbvmcfg, err := config.DecodeVBVMPath(opts.vbvmPath)
			if err != nil {
				return fmt.Errorf("failed to decode vbvm path: %w", err)
			}

			// Create vm snapshot
			if err = vbvmcfg.CreateSnapshot(); err != nil {
				return fmt.Errorf("failed to create VM snapshot: %w", err)
			}
			logrus.Infof("creating VM snapshot at %s", vbvmcfg.SnapshotPath)
			defer func() {
				logrus.Info("cleaning up VM snapshot")
				if err := vbvmcfg.RemoveSnapshot(); err != nil {
					logrus.Warnf("failed to remove snapshot: %v", err)
				}
			}()

			if err := opts.parseDisplay(); err != nil {
				return err
			}

			vmcfg, err := config.NewMacVMConf(
				vbvmcfg,
				&config.VMOptions{
					DisplayWidth:  opts.width,
					DisplayHeight: opts.height,
					Shares:        []config.ShareDir{{Dir: shared.Path(), Tag: "machbox", ReadOnly: true}},
					Network:       opts.parseNetwork(),
				})
			if err != nil {
				return fmt.Errorf("failed to create VM config: %w", err)
			}

			return safetyRunVM(ctx, &opts.vmOptions, vmcfg,
				func(vmi *vm.VMInstance) {
					if err := vmi.StartVsockServer(
						analyzeHandler(vmi, opts)); err != nil {
						logrus.Errorf("failed to start analyze vsock listener: %v", err)
					}
				})
		},
	}

	bindVMFlags(cmd, &opts.vmOptions)

	cmd.Flags().StringVar(&opts.password, "password", "", "password for encrypted archives")
	cmd.Flags().IntVar(&opts.timeout, "timeout", 60, "")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func analyzeHandler(vmi *vm.VMInstance, opts *analyzeOption) func(net.Conn) {
	return func(nc net.Conn) {
		hostconn := vsock.HostConnWrap(nc)
		defer hostconn.Close()

		defer func() {
			logrus.Info("analysis complete, shutting down VM")
			_ = vmi.Shutdown()
		}()

		info, err := hostconn.GuestHandshake()
		if err != nil {
			logrus.Errorf("guest handshake failed: %v", err)
			return
		}

		opts.workpath, opts.sharepath, err = hostconn.SetWorkdir()
		if err != nil {
			logrus.Errorf("%v", err)
			return
		}
		logrus.Infof("set WorkDir: %s, ShareDir: %s", opts.workpath, opts.sharepath)

		retp := report.New(info)
		if err := runStaticTask(hostconn, opts, retp); err != nil {
			logrus.Errorf("%v", err)
			return
		}

		if err := runDynamicTask(hostconn, opts, retp); err != nil {
			logrus.Errorf("%v", err)
		}

		if err := retp.Save(); err != nil {
			logrus.Errorf("failed to save report to db: %v", err)
		}
	}
}

func runDynamicTask(conn *vsock.HostConn,
	opts *analyzeOption,
	retp *report.Parser) error {

	logrus.Infoln("run dynamic analysis task")

	pcikSample, pickTyp := retp.GetPickeFile()
	if pcikSample != opts.vmSamplePath() {
		logrus.Infof("archive main sample resolved to: %s", pcikSample)
	}

	if pcikSample == "" {
		logrus.Warnf("no executable found, skipping dynamic analysis")
		return nil
	}

	if pickTyp == "mach-o" {
		if _, err := conn.RunTask(&protocol.Task{
			Command: "chmod",
			Args:    []string{"+x", pcikSample},
			WorkDir: opts.workpath,
		}); err != nil {
			return err
		}
	}

	dynamicArgs := []string{"run", "-ds",
		filepath.Join(opts.sharepath, "DTrace", "network.d"), "-o", "-", pcikSample}
	dynamicArgs = append(dynamicArgs, opts.sampleArgs...)

	task := &protocol.Task{
		Command: filepath.Join(opts.sharepath, "dynamictool"),
		Args:    dynamicArgs,
		WorkDir: opts.workpath,
		Timeout: opts.timeout}

	reader, err := conn.RunStreamTask(task)
	if err != nil {
		return err
	}
	defer reader.Close()

	return retp.ParseDynamicResult(reader)
}

func runStaticTask(conn *vsock.HostConn,
	opts *analyzeOption,
	retp *report.Parser) error {

	logrus.Infoln("run static analysis task")

	args := []string{}
	if opts.password != "" {
		args = append(args, "--password", opts.password)
	}
	args = append(args, opts.vmSamplePath())

	task := &protocol.Task{
		Command: filepath.Join(opts.sharepath, "statictool"),
		Args:    args,
		WorkDir: opts.workpath,
		Timeout: opts.timeout}

	output, err := conn.RunTask(task)
	if err != nil {
		return err
	}
	return retp.StaticResult(output, opts.vmSamplePath(), opts.workpath)
}
