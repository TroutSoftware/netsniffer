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
	"strings"

	"golang.org/x/tools/txtar"
	"rsc.io/script"
)

// TODO rewrite with a bit more manners
func main() {
	mot := flag.String("t", "", "Module under test")
	tpath := flag.String("tpath", "testt;tests", "Search path for test cases")
	only := flag.String("run", "", "Only run script matching this regular expression")
	sanitize := flag.String("sanitize", "address", "Run with sanitizers: address, none, thread")
	flag.Parse()

	tpathlist := strings.Split(*tpath, ";")
	tests_failed := 0
	tests_succeed := 0
	tests_skipped := 0

	ng := script.NewEngine()
	ng.Cmds["pcap"] = PCAP(LoadSanitize(*sanitize))
	ng.Cmds["skip"] = Skip()

	wd, err := os.Getwd()
	if err != nil {
		errf("cannot grok current wd: %s", err)
	}

	var files []string

	for _, path := range tpathlist {
		tmp, err := filepath.Glob(path + "/*.script")
		files = append(files, tmp...)
		if err != nil {
			errf("could not find tests: %s", err)
		}
	}
	var mtch *regexp.Regexp
	if *only != "" {
		var err error
		mtch, err = regexp.Compile(*only)
		if err != nil {
			errf("invalid filter regexp %s: %s", *only, err)
		}
	}

	if *sanitize != "none" {
		// TODO: Set asanlib to full path to libasan.so
		//    out, err := exec.Command("gcc", "-print-file-name=libasan.so").Output()
		//    if err != nil {
		//      errf("cannot get libasan from gcc: %s", err)
		//    }
		//    asanlib = strings.TrimSpace(string(out))
	}

	for _, f := range files {
		base := filepath.Base(f)
		base = base[:len(base)-len(".script")]
		test_dir := filepath.Dir(f)

		if mtch != nil && !mtch.MatchString(base) {
			continue
		}

		fmt.Fprintf(os.Stderr, "---- TEST_%s", base)

		dir, err := os.MkdirTemp("", "sh3env_"+base)
		if err != nil {
			errf("cannot create temporary directory: %s", err)
		}

		ar, err := txtar.ParseFile(f)
		if err != nil {
			errf("script is not a valid sh3 script: %s", err)
		}

		for _, tf := range ar.Files {
			err := os.WriteFile(filepath.Join(dir, tf.Name), tf.Data, 0644)
			if err != nil {
				errf("cannot create file %s: %s", tf.Name, err)
			}
		}

		// TODO make this part of copy
		if err := os.Mkdir(filepath.Join(dir, "p"), 0755); err != nil {
			errf("cannot create temporary structure: %s", err)
		}

		if _, err := copy(*mot, filepath.Join(dir, "p/"+filepath.Base(*mot))); err != nil {
			errf("cannot copy module: %s -> %s :%s", *mot, filepath.Join(dir, *mot), err)
		}

		st, err := script.NewState(context.Background(), dir, []string{fmt.Sprintf("exedir=%s", wd), fmt.Sprintf("testdir=%s", wd+"/"+test_dir)})
		if err != nil {
			errf("cannot start new script: %s", err)
		}

		ts := bytes.NewReader(ar.Comment)
		if err := ng.Execute(st, f, bufio.NewReader(ts), os.Stderr); err != nil {
			var se skipError
			if skip := errors.As(err, &se); skip {
				tests_skipped++
				if se.msg != "" {
					fmt.Fprintf(os.Stdout, "Skipping test\n")
				} else {
					fmt.Fprintf(os.Stdout, "Skipping test: %s\n", se.msg)
				}
			} else {
				fmt.Fprintf(os.Stderr, "\x1b[1;31mTest Failure: %s\x1b[0m\n", err)
				tests_failed++
			}
		} else {
			tests_succeed++
		}

		os.RemoveAll(dir)
	}

	fmt.Fprintf(os.Stdout, "%d of %d tests passed %d skipped\n", tests_succeed, (tests_succeed + tests_failed), tests_skipped)

	if 0 != tests_failed {
		fmt.Fprintf(os.Stdout, "One or more tests FAILED!!!!\n")
	} else {
		fmt.Fprintf(os.Stdout, "--All tests are green--\n")
	}

}

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

func errf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}

// TODO pass env variable to script, for use in conditionals
type CompileOpt func(args, env []string) (nargs, nenv []string)

func LoadSanitize(stz string) CompileOpt {
	switch stz {
	case "none":
		return func(args, env []string) (nargs []string, nenv []string) {
			return args, env
		}

	case "address":
		return func(args, env []string) (nargs []string, nenv []string) {
			return args, append(env, "LD_PRELOAD="+asanlib)
		}

	default:
		panic("Not implemented")
	}
}
