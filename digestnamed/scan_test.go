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

package digestnamed

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestScanDirectory(t *testing.T) {
	cases := scanTest{
		{
			name:     "expectPass/md5-" + md5DigestOf("md5"),
			contents: "md5",
		},
		{
			name:     "expectPass/md5-" + md5DigestOf("md5") + ".ext",
			contents: "md5",
		},
		{
			name:     "expectPass/sha1-" + sha1DigestOf("sha1"),
			contents: "sha1",
		},
		{
			name:     "expectPass/sha1-" + sha1DigestOf("sha1") + ".ext",
			contents: "sha1",
		},
		{
			name:     "expectPass/sha256-" + sha256DigestOf("sha256"),
			contents: "sha256",
		},
		{
			name:     "expectPass/sha256-" + sha256DigestOf("sha256") + ".ext",
			contents: "sha256",
		},
		{
			name:       "expectFail/not-a-hash",
			contents:   "foo",
			expectFail: true,
		},
		{
			name:       "expectFail/misMatch-" + sha1DigestOf("mis"),
			contents:   "match",
			expectFail: true,
		},
		{
			name:       "expectFail/misMatch-" + sha256DigestOf("mis"),
			contents:   "match",
			expectFail: true,
		},
		{
			name:       "expectFail/misMatch-" + md5DigestOf("mis"),
			contents:   "match",
			expectFail: true,
		},
		{
			name:          "expectSkipped/ignoreme-aaaaffff.css",
			contents:      "bar",
			expectSkipped: true,
		},
		{
			name:          "expectSkipped/ignoreme-aaaaffff.js",
			contents:      "bar",
			expectSkipped: true,
		},
		{
			name:             "expectNonRegular/relative",
			contents:         "../expectFail/not-a-hash",
			expectNonRegular: true,
		},
		{
			name:             "expectNonRegular/absolute",
			contents:         "/tmp",
			expectNonRegular: true,
		},
	}

	if os.Geteuid() != 0 {
		// We trigger the error by chmod 0, which doesn't stop root.
		// These tests may get run as root.
		cases = append(cases, testFile{
			name:        "expectError/bar-" + sha1DigestOf("bar"),
			contents:    "bar",
			expectError: true,
		})
	}

	err := cases.run(t.Cleanup, []string{`ignoreme-[0-9a-f]{8}\.(?:css|js)`})
	if err != nil {
		t.Fatal(err)
	}
}

type scanTest []testFile

func (st scanTest) run(registerCleanup func(func()), ignorePatterns []string) error {
	scanner, err := NewScanner(ignorePatterns)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "lint-scan-test-directory-*")
	if err != nil {
		return err
	}
	registerCleanup(func() {
		cleanupErr := os.RemoveAll(dir)
		if cleanupErr != nil {
			panic(cleanupErr)
		}
	})
	err = st.setup(dir)
	if err != nil {
		return fmt.Errorf("setup failed: %w", err)
	}
	results, err := scanner.ScanDirectory(dir)
	if err != nil {
		return err
	}
	return st.check(results, dir)
}

func (st scanTest) setup(dir string) error {
	for _, tf := range st {
		err := tf.setup(dir)
		if err != nil {
			return err
		}
	}
	return nil
}

func (st scanTest) check(report Report, dir string) error {
	var expectPassed, expectSkipped, expectFailed, expectNonRegular, expectFileErrors int

	for _, tf := range st {
		err := tf.check(report, dir)
		if err != nil {
			return err
		}

		switch {
		case tf.expectFail:
			expectFailed++
		case tf.expectError:
			expectFileErrors++
		case tf.expectNonRegular:
			expectNonRegular++
		case tf.expectSkipped:
			expectSkipped++
		default:
			expectPassed++
		}
	}

	if expectNonRegular != len(report.NonRegular) {
		return fmt.Errorf("expected %d NonRegular, got %d", expectNonRegular, len(report.NonRegular))
	}
	if expectFailed != len(report.Failed) {
		return fmt.Errorf("expected %d Failed, got %d", expectFailed, len(report.Failed))
	}
	if expectPassed != len(report.Passed) {
		return fmt.Errorf("expected %d Passed, got %d", expectPassed, len(report.Passed))
	}
	if expectSkipped != len(report.Skipped) {
		return fmt.Errorf("expected %d Skipped, got %d", expectSkipped, len(report.Skipped))
	}
	if expectFileErrors != len(report.FileErrors) {
		return fmt.Errorf("expected %d FileErrors, got %d", expectFileErrors, len(report.FileErrors))
	}

	return nil
}

type testFile struct {
	name             string
	contents         string
	expectNonRegular bool
	expectError      bool
	expectFail       bool
	expectSkipped    bool
}

func (tf testFile) setup(dir string) error {
	path := filepath.Join(dir, tf.name)
	if strings.Contains(tf.name, "/") {
		err := os.MkdirAll(filepath.Dir(path), 0700)
		if err != nil {
			return err
		}
	}

	if tf.expectNonRegular {
		// trigger non-regular case by making a symlink
		return os.Symlink(tf.contents, path)
	}

	if tf.expectError {
		// trigger read error case by chmod 0
		return ioutil.WriteFile(path, []byte(tf.contents), 0)
	}

	return ioutil.WriteFile(path, []byte(tf.contents), 0400)
}

func (tf testFile) check(report Report, dir string) error {
	path := filepath.Join(dir, tf.name)

	if tf.expectNonRegular {
		i := sort.SearchStrings(report.NonRegular, path)
		if report.NonRegular[i] != path {
			return fmt.Errorf("missing from NonRegular: %q", path)
		}
		return nil
	}

	if tf.expectError {
		if _, ok := report.FileErrors[path]; !ok {
			return fmt.Errorf("missing from FileErrors: %q", path)
		}
		return nil
	}

	if tf.expectFail {
		i := sort.SearchStrings(report.Failed, path)
		if report.Failed[i] != path {
			return fmt.Errorf("missing from Failed: %q", path)
		}
		return nil
	}

	if tf.expectSkipped {
		i := sort.SearchStrings(report.Skipped, path)
		if report.Skipped[i] != path {
			return fmt.Errorf("missing from Skipped: %q", path)
		}
		return nil
	}

	i := sort.SearchStrings(report.Passed, path)
	if report.Passed[i] != path {
		return fmt.Errorf("missing from Passed: %q", path)
	}
	return nil
}

func md5DigestOf(s string) string {
	digest := md5.Sum([]byte(s))
	return hex.EncodeToString(digest[:])
}

func sha1DigestOf(s string) string {
	digest := sha1.Sum([]byte(s))
	return hex.EncodeToString(digest[:])
}

func sha256DigestOf(s string) string {
	digest := sha256.Sum256([]byte(s))
	return hex.EncodeToString(digest[:])
}
