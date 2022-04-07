// Copyright 2022 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/alecthomas/kong"
	"github.com/retailnext/staticassetlint/digestnamed"
)

var CLI struct {
	Verbose bool     `flag:"" help:"Print the names of files with valid names."`
	Skip    []string `flag:"" sep:"none" help:"Skip checking file with names matching any of these regex patterns."`
	Dirs    []string `arg:"" required:"" help:"Directories containing files to check." type:"existingdir"`
}

func main() {
	_ = kong.Parse(&CLI)

	scanner, err := digestnamed.NewScanner(CLI.Skip)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
		os.Exit(1)
	}

	var exitError bool

	reports := make([]digestnamed.Report, len(CLI.Dirs))
	for i := range CLI.Dirs {
		var err error
		reports[i], err = scanner.ScanDirectory(CLI.Dirs[i])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
			exitError = true
		}
	}

	for _, report := range reports {
		for _, fileError := range report.FileErrors {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", fileError.Error())
			exitError = true
		}
	}

	// If we were unable to complete the walk, or there were files we failed to read, bail early.
	// This is a different kind of failure than if there are files that don't pass.
	if exitError {
		os.Exit(1)
	}

	var passed, skipped, failed, nonRegular []string
	for _, report := range reports {
		passed = append(passed, report.Passed...)
		skipped = append(skipped, report.Skipped...)
		failed = append(failed, report.Failed...)
		nonRegular = append(nonRegular, report.NonRegular...)
	}

	if len(nonRegular) > 0 {
		sort.Strings(nonRegular)
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: found %d non-regular files:\n", len(nonRegular))
		for _, path := range nonRegular {
			_, _ = fmt.Fprintf(os.Stderr, "\t%q\n", path)
		}
		exitError = true
	}

	if len(failed) > 0 {
		sort.Strings(failed)
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: found %d files with invalid names:\n", len(failed))
		for _, path := range failed {
			_, _ = fmt.Fprintf(os.Stderr, "\t%q\n", path)
		}
		exitError = true
	}

	if CLI.Verbose {
		sort.Strings(skipped)
		_, _ = fmt.Fprintf(os.Stdout, "INFO: skipped checking %d files:\n", len(skipped))
		for _, path := range skipped {
			_, _ = fmt.Fprintf(os.Stdout, "\t%q\n", path)
		}
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "INFO: skipped checking %d files\n", len(skipped))
	}

	if len(passed) == 0 && len(skipped) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: no files with valid names found\n")
		return
	}

	if CLI.Verbose {
		sort.Strings(passed)
		_, _ = fmt.Fprintf(os.Stdout, "INFO: found %d files with valid names:\n", len(passed))
		for _, path := range passed {
			_, _ = fmt.Fprintf(os.Stdout, "\t%q\n", path)
		}
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "INFO: found %d files with valid names\n", len(passed))
	}

	if exitError {
		os.Exit(1)
	}
}
