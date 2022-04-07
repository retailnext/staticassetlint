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
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.uber.org/multierr"
)

func NewScanner(skipPatterns []string) (Scanner, error) {
	compiledPatterns, err := makeIgnorePatterns(skipPatterns)
	if err != nil {
		return Scanner{}, err
	}
	return Scanner{compiledPatterns}, nil
}

type Scanner struct {
	ignoreMatchingFileNames ignorePatterns
}

// ScanDirectory checks that the files in a directory and its children are named based on their digest contents.
// This only returns an error if there was a problem traversing the directory and its children;
// any errors opening/reading files are reported in the Report instead.
func (s Scanner) ScanDirectory(path string) (Report, error) {
	var results Report
	err := filepath.WalkDir(path, s.walkDirFunc(&results))
	if err != nil {
		return Report{}, err
	}
	sort.Strings(results.Passed)
	sort.Strings(results.Skipped)
	sort.Strings(results.NonRegular)
	sort.Strings(results.Failed)
	return results, nil
}

func (s Scanner) walkDirFunc(report *Report) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		mode := d.Type()
		if mode.IsDir() {
			// Permit traversal into directories; avoid logging as non-regular.
			return nil
		}
		if !mode.IsRegular() {
			// Log as non-regular. This may be treated as a failure.
			report.NonRegular = append(report.NonRegular, path)
			return nil
		}

		if s.ignoreMatchingFileNames.MatchString(filepath.Base(path)) {
			report.Skipped = append(report.Skipped, path)
			return nil
		}

		report.handleFile(path)

		return nil
	}
}

type Report struct {
	// Passed files contain their digest in the filename
	Passed []string

	// Skipped files weren't checked because they matched an allowed pattern
	Skipped []string

	// Failed files don't contain a matching digest in the filename
	Failed []string

	// NonRegular files cannot be checked because opening them is probably unsafe
	NonRegular []string

	FileErrors map[string]error
}

func (s *Report) handleFile(path string) {
	expectedDigest := extractHexDigest(path)
	var hashes []hash.Hash
	switch len(expectedDigest) {
	case 64:
		hashes = []hash.Hash{sha256.New()}
	case 40:
		hashes = []hash.Hash{sha1.New()}
	case 32:
		hashes = []hash.Hash{md5.New()}
	default:
		s.Failed = append(s.Failed, path)
		return
	}
	actualDigests, err := getDigests(path, hashes)
	if err != nil {
		if s.FileErrors == nil {
			s.FileErrors = make(map[string]error)
		}
		s.FileErrors[path] = err
		return
	}
	for _, digest := range actualDigests {
		if digest == expectedDigest {
			s.Passed = append(s.Passed, path)
			return
		}
	}
	s.Failed = append(s.Failed, path)
}

func extractHexDigest(name string) string {
	name = filepath.Base(name)
	return strings.ToLower(hexPattern.FindString(name))
}

func getDigests(path string, hashes []hash.Hash) (digests []string, err error) {
	var f *os.File
	f, err = os.Open(path)
	if err != nil {
		return
	}
	defer multierr.AppendInvoke(&err, multierr.Close(f))

	writers := make([]io.Writer, len(hashes))
	for i := range hashes {
		hashes[i].Reset()
		writers[i] = hashes[i]
	}
	w := io.MultiWriter(writers...)

	_, err = io.Copy(w, f)
	if err != nil {
		return
	}
	digests = make([]string, len(hashes))
	for i := range hashes {
		digests[i] = hex.EncodeToString(hashes[i].Sum(nil))
	}
	return
}
