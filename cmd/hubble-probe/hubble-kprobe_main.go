package main

import (
	"github.com/covalentio/hubble-probe/pkg/bpf"
	"github.com/covalentio/hubble-probe/pkg/observer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"context"
	"math"

	"golang.org/x/sys/unix"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command
)

func configureResourceLimits() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
}

func hubbleMainExecute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bpf.CheckOrMountFS("")
	configureResourceLimits()
	kprobe := observer.NewObserverKprobe(observerDir)
	kprobe.Start()
}

func init() {
	cmd = &cobra.Command{
		Use:   "hubble-probe SOURCE_DIR BUCKET",
		Short: "Hubble probe",
		Run: func(cmd *cobra.Command, args []string) {
			hubbleKProbeExecute()
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP("debug", "d", true, "Enable debug messages")
	viper.BindPFlags(flags)
}

func hubbleKProbeMain() {
	cmd.Execute()
}
