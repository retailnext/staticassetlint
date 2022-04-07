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

type ignorePatternsTestCase struct {
	patterns            []string
	expectCreateFailure bool
	shouldMatch         []string
	shouldNotMatch      []string
}

func (c ignorePatternsTestCase) check() error {
	compiled, err := makeIgnorePatterns(c.patterns)
	if c.expectCreateFailure {
		if err == nil {
			return fmt.Errorf("expected creating patterns=%+v to fail, got nil error", c.patterns)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating patterns=%+v failed: %w", c.patterns, err)
	}
	for _, s := range c.shouldMatch {
		if !compiled.MatchString(s) {
			return fmt.Errorf("expected patterns=%+v to match %q", c.patterns, s)
		}
	}
	for _, s := range c.shouldNotMatch {
		if compiled.MatchString(s) {
			return fmt.Errorf("expected patterns=%+v to match %q but it did not", c.patterns, s)
		}
	}
	return nil
}

func TestIgnorePatterns(t *testing.T) {
	cases := []ignorePatternsTestCase{
		{
			patterns: []string{
				".*",
			},
			expectCreateFailure: true,
		},
		{
			patterns: []string{
				".+",
			},
			expectCreateFailure: true,
		},
		{
			patterns:       nil,
			shouldNotMatch: []string{"", "."},
		},
		{
			patterns: []string{
				"[0-9a-f]{8}.gif",
			},
			shouldMatch: []string{
				"aaaaaaaa.gif",
			},
			shouldNotMatch: []string{
				".DS_Store",
			},
		},
	}
	for _, tc := range cases {
		if err := tc.check(); err != nil {
			t.Fatal(err)
		}
	}
}
