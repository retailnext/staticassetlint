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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type ignorePatterns []*regexp.Regexp

func (i ignorePatterns) MatchString(s string) bool {
	for _, r := range i {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}

func makeIgnorePatterns(patterns []string) (ignorePatterns, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, expr := range patterns {
		r, err := regexp.Compile("^" + expr + "$")
		if err != nil {
			return nil, err
		}
		err = validateIgnoreRegexp(r)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func makeHexRegexp(lengths ...int) *regexp.Regexp {
	sortedLengths := append([]int(nil), lengths...)
	sort.Sort(sort.Reverse(sort.IntSlice(sortedLengths)))

	var acc strings.Builder
	for i, digits := range sortedLengths {
		if i > 0 {
			if _, err := acc.WriteRune('|'); err != nil {
				panic(err)
			}
		}
		if _, err := fmt.Fprintf(&acc, "[0-9a-f]{%d}|[0-9A-F]{%d}", digits, digits); err != nil {
			panic(err)
		}
	}
	return regexp.MustCompile(acc.String())
}

var hexPattern = makeHexRegexp(64, 40, 32)

var namesIgnorePatternsMustNotMatch = []string{
	"",
	"''",
	".",
	"..",
	".DS_Store",
	".htaccess",
	"\"\"",
	"favicon.ico",
	"index.html",
	"robots.txt",
}

func validateIgnoreRegexp(r *regexp.Regexp) error {
	for _, s := range namesIgnorePatternsMustNotMatch {
		if r.MatchString(s) {
			return fmt.Errorf("pattern %q is invalid because it matched %q", r.String(), s)
		}
	}
	return nil
}
