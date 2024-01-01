package main

import (
	"os/exec"
	"strings"

	"github.com/romaindoumenc/script"
)

var snortloc = "/opt/snort/bin/snort"

// PCAP runs snort against PCAP files, without any rule.
// $(SNORT) -v -c cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all
func PCAP() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "run snort against pcap files",
			Args:    "files...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, script.ErrUsage
			}

			var stdoutBuf, stderrBuf strings.Builder

			cmd := exec.CommandContext(s.Context(), snortloc,
				"-c", s.Path("cfg.lua"),
				"--pedantic",
				"--plugin-path", "p",
				"-A", "talos",
				"--pcap-list", strings.Join(args, " "),
				"--warn-all",
			)
			cmd.Dir = s.Getwd()
			// TODO only preload if asan is set
			cmd.Env = append(s.Environ(), "LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/13/libasan.so")
			cmd.Stdout = &stdoutBuf
			cmd.Stderr = &stderrBuf
			err := cmd.Start()
			if err != nil {
				return nil, err
			}

			wait := func(s *script.State) (stdout, stderr string, err error) {
				err = cmd.Wait()
				return stdoutBuf.String(), stderrBuf.String(), err
			}
			return wait, nil
		},
	)
}
