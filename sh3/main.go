package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/tools/txtar"
	"rsc.io/script"
)

const usage = `
Usage
  sh3 [-r REGEXP] [-C DIR] MODULE

Options
  --run, -r         Only run tests matching REGEXP
  --break-on-error  Terminate on the first error encountered
  --chdir, -C       Change do DIR before executing the script

sh3 runs the tests scripts present in MODULE/tests.

Each script consists of a txtar archive with the files required to run the test.
All archives are extracted to a temporary folder (given a temporary directory T,
a file rule/lua.rule in the archive will be copied at T/rule/lua.rule).
Furthermore:
 - the "pcaps" directory is symlinked at T/pcaps, and can be referred in scripts.

The test is then executed in the T directory (the test script must only refer to local files).
`

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		only   string
		wd     string
		notest bool
		tdir   string
	)
	flag.StringVar(&only, "run", "", "Only run script matching this regular expression")
	flag.StringVar(&only, "r", "", "Only run script matching this regular expression")
	flag.StringVar(&wd, "C", "", "Change to dir")
	flag.StringVar(&wd, "chdir", "", "Change to dir")
	flag.BoolVar(&notest, "notest", false, "No test")
	flag.StringVar(&tdir, "tdir", "", "tdir")
	break_on_err := flag.Bool("break-on-error", false, "Set if test run should be aborted on first error")
	flag.Parse()

	var fail = lipgloss.NewStyle().Foreground(lipgloss.Color("#ea580c"))
	var pass = lipgloss.NewStyle().Foreground(lipgloss.Color("#6ee7b7"))

	modules := flag.Args()

	tests_failed := 0
	tests_succeed := 0
	tests_skipped := 0

	ng := script.NewEngine()
	ng.Cmds["pcap"] = snort()
	ng.Cmds["skip"] = Skip()
	ng.Cmds["cmp"] = Eq()

	if wd == "" {
		w, err := os.Getwd()
		if err != nil {
			errf("cannot grok current wd: %s", err)
		}
		wd = w
	}
	if !filepath.IsAbs(wd) {
		var err error
		wd, err = filepath.Abs(wd)
		if err != nil {
			errf("cannot get an absolute path: %s", err)
		}
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
	for _, tscrpt := range scripts {
		tscrpt, err := filepath.Abs(tscrpt)
		if err != nil {
			errf("cannot get absolute path: %s", err)
		}

		base := filepath.Base(tscrpt)
		base = base[:len(base)-len(".script")]

		// ignore skipped tests
		if mtch != nil && !mtch.MatchString(base) {
			tests_skipped++
			continue
		}

		fmt.Fprintf(os.Stderr, "---- TEST_%s ", base)

		// create temporary environment, extract txtar files
		test_dir, err := os.MkdirTemp(tdir, "sh3env_")
		if err != nil {
			errf("cannot create temporary directory: %s", err)
		}

		ar, err := txtar.ParseFile(tscrpt)
		if err != nil {
			errf("script is not a valid sh3 script: %s", err)
		}

		for _, tf := range ar.Files {
			err := os.WriteFile(filepath.Join(test_dir, tf.Name), tf.Data, 0644)
			if err != nil {
				errf("cannot create file %s: %s", tf.Name, err)
			}
		}

		// optionally include testdata folder
		if _, err := os.Stat(filepath.Dir(tscrpt) + "/testdata"); err == nil {
			if err := os.Symlink(filepath.Dir(tscrpt)+"/testdata", filepath.Join(test_dir, "testdata")); err != nil {
				errf("cannot symlink for /testdata: %s", err)
			}
		}

		if notest {
			continue
		}

		// execute script, check output
		env := []string{}
		st, err := script.NewState(context.Background(), test_dir, env)
		if err != nil {
			errf("cannot start new script: %s", err)
		}

		ts := bytes.NewReader(ar.Comment)
		var buf bytes.Buffer
		if err := ng.Execute(st, tscrpt, bufio.NewReader(ts), &buf); err != nil {
			var se skipError
			if skip := errors.As(err, &se); skip {
				tests_skipped++
				if se.msg != "" {
					fmt.Fprintf(os.Stderr, "Skipping test\n")
				} else {
					fmt.Fprintf(os.Stderr, "Skipping test: %s\n", se.msg)
				}
			} else {
				fmt.Fprintln(os.Stderr, fail.Render("FAIL"))
				fmt.Fprintf(os.Stderr, "%s\n", err)
				io.Copy(os.Stderr, &buf)
				fmt.Fprintf(os.Stderr, "Test output dir: %s\n", test_dir)

				tests_failed++
				if *break_on_err {
					break
				}
			}
		} else {
			tests_succeed++
			fmt.Fprintln(os.Stderr, pass.Render("ok"))
			os.RemoveAll(test_dir)
		}

		buf.Reset()
		if err := st.CloseAndWait(&buf); err != nil {
			io.Copy(os.Stderr, &buf)
		}
	}

	fmt.Fprintf(os.Stderr, "%d of %d tests passed %d skipped\n", tests_succeed, test_count, tests_skipped)

	if 0 != tests_failed {
		fmt.Fprintf(os.Stderr, "One or more tests FAILED!!!!\n")
	} else {
		fmt.Fprintln(os.Stderr, pass.Render("--All tests are green--"))
	}
}

func errf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}
