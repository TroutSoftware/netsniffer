package main

import (
	"os/exec"
	"strings"

	"rsc.io/script"
)

var snortloc = "/opt/snort/bin/snort"

var asanlib string

// PCAP runs snort against PCAP files, without any rule.
// $(SNORT) -v -c cfg.lua --plugin-path p -A talos --pcap-dir ../../test_data --warn-all
func PCAP(opts ...CompileOpt) script.Cmd {
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
				"--plugin-path", "p",
				"-A", "talos",
				"--pcap-list", strings.Join(args, " "),
				"--warn-all",
			)
			cmd.Dir = s.Getwd()
			// TODO only preload if asan is set
			cmd.Env = s.Environ()
			for _, o := range opts {
				cmd.Args, cmd.Env = o(cmd.Args, cmd.Env)
			}

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

func Skip() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "skip the current test",
			Args:    "[msg]",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) > 1 {
				return nil, script.ErrUsage
			}
			if len(args) == 0 {
				return nil, skipError{""}
			}
			return nil, skipError{args[0]}
		})
}

type skipError struct{ msg string }

func (err skipError) Error() string { return err.msg }
