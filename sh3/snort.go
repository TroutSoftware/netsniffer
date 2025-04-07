package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"rsc.io/script"
)

var snortloc = "/opt/snort/bin/snort"
var luascript = "/opt/snort/include/snort/lua/?.lua;;"

// PCAP runs snort against PCAP files.
// A default configuration, optionally in multiple files, is attached from the txtar by the runner.

func PCAP(opts ...CompileOpt) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "run snort against pcap files",
			Args:    "[-expect-fail] files...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var file_list []string
			var expect_fail bool

			fs := flag.NewFlagSet("pcap", flag.ContinueOnError)
			fs.BoolVar(&expect_fail, "expect-fail", false, "expect failure")
			if err := fs.Parse(args); err != nil {
				return nil, err
			}
			file_list = fs.Args()

			if env_snort := os.Getenv("SNORT"); len(env_snort) > 0 {
				snortloc = env_snort
			}

			lib_path := os.Getenv("LD_LIBRARY_PATH")
			daq_path := os.Getenv("SNORT_DAQ_PATH")

			if len(file_list) < 1 {
				return nil, script.ErrUsage
			}

			var stdoutBuf, stderrBuf strings.Builder

			cmd := exec.CommandContext(s.Context(), snortloc,
				"-c", s.Path("cfg.lua"),
				"--script-path", ".",
				"--plugin-path", "p",
				"--pcap-list", strings.Join(file_list, " "),
				"--warn-all",
			)
			// TODO: Fix this if so not almost like the above cmd :=
			if len(daq_path) > 0 {
				cmd = exec.CommandContext(s.Context(), snortloc,
					"-c", s.Path("cfg.lua"),
					"--script-path", ".",
					"--plugin-path", "p",
					"--pcap-list", strings.Join(file_list, " "),
					"--warn-all",
					"--daq-dir", daq_path,
				)
			}

			cmd.Dir = s.Getwd()
			// TODO only preload if asan is set
			cmd.Env = append(s.Environ(), "LUA_PATH="+luascript)

			if len(lib_path) > 0 {
				cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+lib_path)
			}

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

				if expect_fail && err != nil {
					err = nil
				} else if expect_fail {
					err = fmt.Errorf("Expected error, but it didn't happen")
				}

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
