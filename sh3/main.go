package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/tools/txtar"
	"rsc.io/script"
)

const usage = `
Usage
  sh3 [-r REGEXP] [-C DIR] MODULE

Options
  --run, -r         Only run tests matching REGEXP
  --debug, -d       Use debug build (by default release ones)
  --break-on-error  Terminate on the first error encountered
  --chdir, -C       Change do DIR before executing the script

sh3 runs the tests scripts present in MODULE/tests.

Each script consists of a txtar archive with the files required to run the test.
All archives are extracted to a temporary folder (given a temporary directory T,
a file rule/lua.rule in the archive will be copied at T/rule/lua.rule).
Furthermore:
 - the "p/install/{bin,lib,include}" directory is symlinked at T/{bin,lib,include} 
   (snort and dependencies are available in PATH and LDPATH).
 - the "p/release/tm.so" is copied to "T/p/tm.so" (unless --debug is given)
 - the "pcaps" directory is symlinked at T/pcaps, and can be referred in scripts.

The test is then executed in the T directory (and must only refer to local files).
`

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		only  string
		wd    string
		debug bool
	)
	flag.StringVar(&only, "run", "", "Only run script matching this regular expression")
	flag.StringVar(&only, "r", "", "Only run script matching this regular expression")
	flag.BoolVar(&debug, "debug", false, "Use the debug binary")
	flag.BoolVar(&debug, "d", false, "Use the debug binary")
	flag.StringVar(&wd, "C", "", "Change to dir")
	flag.StringVar(&wd, "chdir", "", "Change to dir")
	break_on_err := flag.Bool("break-on-error", false, "Set if test run should be aborted on first error")
	flag.Parse()

	modules := flag.Args()

	tests_failed := 0
	tests_succeed := 0
	tests_skipped := 0

	ng := script.NewEngine()
	ng.Cmds["pcap"] = PCAP()
	ng.Cmds["skip"] = Skip()

	if wd == "" {
		w, err := os.Getwd()
		if err != nil {
			errf("cannot grok current wd: %s", err)
		}
		wd = w
	}

	var scripts []string
	for _, path := range modules {
		s, err := filepath.Glob(path + "/tests/*.script")
		scripts = append(scripts, s...)
		if err != nil {
			errf("could not find tests: %s", err)
		}
	}

	var mtch *regexp.Regexp
	if only != "" {
		var err error
		mtch, err = regexp.Compile(only)
		if err != nil {
			errf("invalid filter regexp %s: %s", only, err)
		}
	}

	test_count := len(scripts)
	for _, f := range scripts {
		base := filepath.Base(f)
		base = base[:len(base)-len(".script")]

		if mtch != nil && !mtch.MatchString(base) {
			continue
		}

		fmt.Fprintf(os.Stderr, "---- TEST_%s", base)

		test_dir, err := os.MkdirTemp("", "sh3env_")
		if err != nil {
			errf("cannot create temporary directory: %s", err)
		}

		fmt.Println("==> debug tmp dir", test_dir)

		ar, err := txtar.ParseFile(f)
		if err != nil {
			errf("script is not a valid sh3 script: %s", err)
		}

		for _, tf := range ar.Files {
			err := os.WriteFile(filepath.Join(test_dir, tf.Name), tf.Data, 0644)
			if err != nil {
				errf("cannot create file %s: %s", tf.Name, err)
			}
		}

		links := []string{"bin", "include", "lib"}
		for _, l := range links {
			if err := os.Symlink(filepath.Join(wd, "p/install", l), filepath.Join(test_dir, l)); err != nil {
				errf("cannot symlink %s: %s", l, err)
			}
		}
		if err := os.Mkdir(filepath.Join(test_dir, "p"), 0755); err != nil {
			errf("cannot create temporary structure: %s", err)
		}
		mod := "p/release/tm.so"
		if debug {
			mod = "p/debug/tm.so"
		}
		if err := os.Symlink(filepath.Join(wd, mod), filepath.Join(test_dir, "p", "tm.so")); err != nil {
			errf("cannot symlink %s: %s", mod, err)
		}

		env := []string{fmt.Sprintf("LD_LIBRARY_PATH=%s/lib", test_dir)}
		st, err := script.NewState(context.Background(), test_dir, env)
		if err != nil {
			errf("cannot start new script: %s", err)
		}

		ts := bytes.NewReader(ar.Comment)
		if err := ng.Execute(st, f, bufio.NewReader(ts), os.Stderr); err != nil {
			var se skipError
			if skip := errors.As(err, &se); skip {
				tests_skipped++
				if se.msg != "" {
					fmt.Fprintf(os.Stderr, "Skipping test\n")
				} else {
					fmt.Fprintf(os.Stderr, "Skipping test: %s\n", se.msg)
				}
			} else {
				fmt.Fprintf(os.Stderr, "\x1b[1;31mTest Failure: %s\x1b[0m\n", err)
				tests_failed++

				if *break_on_err {
					break
				}
			}
		} else {
			tests_succeed++
			os.RemoveAll(test_dir)
		}
	}

	fmt.Fprintf(os.Stderr, "%d of %d tests passed %d skipped\n", tests_succeed, test_count, tests_skipped)

	if 0 != tests_failed {
		fmt.Fprintf(os.Stderr, "One or more tests FAILED!!!!\n")
	} else {
		fmt.Fprintf(os.Stderr, "\x1b[1;32m--All tests are green--\x1b[0m\n")
	}
}

func errf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}
