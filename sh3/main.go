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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/romaindoumenc/script"
	"golang.org/x/tools/txtar"
)

// TODO rewrite with a bit more manners
func main() {
	output := flag.String("o", "", "Output module name")
	inputs := flag.String("i", "", "Inputs cc and .a files, space-separated")
	only := flag.String("run", "", "Only run script matching this regular expression")
	flag.Parse()

	ng := script.NewEngine()
	ng.Cmds["pcap"] = PCAP()
	ng.Cmds["skip"] = Skip()

	dst := filepath.Join("p/", *output)
	err := compile(
		Include("/opt/snort/include/snort"),
		Module(),
		OptLevel(1),
		Debug(),
		Modern(),
		Sanitize("address"),
		Input(strings.Split(*inputs, " ")...),
		Output(dst),
	)
	if err != nil {
		errf("cannot compile module: %s", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		errf("cannot grok current wd: %s", err)
	}

	files, err := filepath.Glob("tests/*.script")
	if err != nil {
		errf("could not find tests: %s", err)
	}
	var mtch *regexp.Regexp
	if *only != "" {
		var err error
		mtch, err = regexp.Compile(*only)
		if err != nil {
			errf("invalid filter regexp %s: %s", *only, err)
		}
	}

	{
		out, err := exec.Command("gcc", "-print-file-name=libasan.so").Output()
		if err != nil {
			errf("cannot get libasan from gcc: %s", err)
		}
		asanlib = strings.TrimSpace(string(out))
	}

	for _, f := range files {
		base := filepath.Base(f)
		base = base[:len(base)-len(".script")]

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

		if _, err := copy(dst, filepath.Join(dir, dst)); err != nil {
			errf("cannot copy module: %s", err)
		}

		st, err := script.NewState(context.Background(), dir, []string{fmt.Sprintf("moddir=%s", wd)})
		if err != nil {
			errf("cannot start new script: %s", err)
		}

		ts := bytes.NewReader(ar.Comment)
		if err := ng.Execute(st, f, bufio.NewReader(ts), os.Stderr); err != nil {
			var se skipError
			if skip := errors.As(err, &se); skip {
				if se.msg != "" {
					fmt.Fprintf(os.Stdout, "Skipping test\n")
				} else {
					fmt.Fprintf(os.Stdout, "Skipping test: %s\n", se.msg)
				}
			} else {
				fmt.Fprintf(os.Stderr, "\x1b[1;31mTest Failure: %s\x1b[0m\n", err)
			}
		}

		os.RemoveAll(dir)
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

func OptLevel(level int) CompileOpt {
	if level < 0 || level > 2 {
		panic("gcc only has level between 0 and 2")
	}

	return func(args, env []string) ([]string, []string) {
		return append(args, fmt.Sprintf("-O%d", level)), env
	}
}

func Module() CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, "-fPIC", "-shared"), env
	}
}

func Modern() CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, "-Wall", "-Werror", "-Wextra", "-std=c++20"), env
	}
}

func Debug() CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, "-g", "-fno-omit-frame-pointer"), env
	}
}

func Sanitize(stz string) CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, fmt.Sprintf("-fsanitize=%s", stz)), env
	}
}

func Include(dir string) CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, "-I", dir), env
	}
}

func Output(file string) CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, "-o", file), env
	}
}

func Input(files ...string) CompileOpt {
	return func(args, env []string) (nargs []string, nenv []string) {
		return append(args, files...), env
	}
}

func compile(opts ...CompileOpt) error {
	c := exec.Command("g++")
	var env []string
	for _, o := range opts {
		c.Args, env = o(c.Args, env)
	}
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	return c.Run()
}
