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

func TestExtractHexDigest(t *testing.T) {
	cases := map[string]string{
		"vendor-c2293867abd250a96bb64cc0c78ed603.css":                         "c2293867abd250a96bb64cc0c78ed603",
		"vendor-C2293867ABD250A96BB64CC0C78ED603.css":                         "c2293867abd250a96bb64cc0c78ed603",
		"vendor-415ab40ae9b7cc4e66d6769cb2c08106e8293b48.css":                 "415ab40ae9b7cc4e66d6769cb2c08106e8293b48",
		"9e58e1c69c2c77d6be328dd795d7154f25e5ea3718c2c0d0f6ea6017cfb8b3dc.gz": "9e58e1c69c2c77d6be328dd795d7154f25e5ea3718c2c0d0f6ea6017cfb8b3dc",
	}
	for input, expected := range cases {
		result := extractHexDigest(input)
		if result != expected {
			t.Fatalf("input:%q expected:%q result:%q", input, expected, result)
		}
	}
}

func TestScanDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "lint-TestScanDirectory-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupErr := os.RemoveAll(dir)
		if cleanupErr != nil {
			panic(cleanupErr)
		}
	})

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

	err = cases.setup(dir)
	if err != nil {
		t.Fatalf("setup failed: %v+", err)
	}

	results, err := ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = cases.check(results, dir)
	if err != nil {
		t.Fatal(err)
	}
}

type scanTest []testFile

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
	var expectPassed, expectFailed, expectNonRegular, expectFileErrors int

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
