// Copyright Istio Authors
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

package dependencies

import (
	"strings"
	"testing"

	// Create a new network namespace. This will have the 'lo' interface ready but nothing else.
	_ "github.com/howardjohn/unshare-go/netns"
	// Create a new user namespace. This will map the current UID to 0.
	_ "github.com/howardjohn/unshare-go/userns"
	"github.com/vishvananda/netns"
	utilversion "k8s.io/apimachinery/pkg/util/version"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/file"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
)

func TestRunInSandbox(t *testing.T) {
	original := file.AsStringOrFail(t, "/etc/nsswitch.conf")
	var sandboxed string

	originalNetNS, err := netns.Get()
	assert.NoError(t, err)
	var sandboxedNetNS netns.NsHandle

	// Due to unshare-go imports above, this can run
	assert.NoError(t, runInSandbox("", func() error {
		// We should have overwritten this file with /dev/null
		sandboxed = file.AsStringOrFail(t, "/etc/nsswitch.conf")
		sandboxedNetNS, err = netns.Get()
		assert.NoError(t, err)
		return nil
	}))
	after := file.AsStringOrFail(t, "/etc/nsswitch.conf")
	assert.Equal(t, sandboxed, "")
	assert.Equal(t, original, after)
	assert.Equal(t, originalNetNS.Equal(sandboxedNetNS), true)
}

func TestExecuteXTablesCommentPrevention(t *testing.T) {
	deps := &RealDependencies{}
	logger := log.FindScope(log.DefaultScopeName)

	// Create a mock iptables version for testing
	mockVersion := &IptablesVersion{
		DetectedBinary:        "iptables",
		DetectedSaveBinary:    "iptables-save",
		DetectedRestoreBinary: "iptables-restore",
		Version:               utilversion.MustParseGeneric("1.8.4"),
		Legacy:                true,
		ExistingRules:         false,
	}

	testCases := []struct {
		name        string
		args        []string
		expectError bool
		errorText   string
	}{
		{
			name:        "comment module with -m comment flag should be rejected",
			args:        []string{"-t", "nat", "-A", "INPUT", "-m", "comment", "--comment", "test comment"},
			expectError: true,
			errorText:   "iptables comment flags are not allowed: found '-m comment' in arguments",
		},
		{
			name:        "standalone --comment flag should be rejected",
			args:        []string{"-t", "nat", "-A", "INPUT", "--comment", "test comment"},
			expectError: true,
			errorText:   "iptables comment flags are not allowed: found '--comment' in arguments",
		},
		{
			name:        "comment flag at the end should be rejected",
			args:        []string{"-t", "nat", "-A", "INPUT", "-j", "ACCEPT", "-m", "comment"},
			expectError: true,
			errorText:   "iptables comment flags are not allowed: found '-m comment' in arguments",
		},
		{
			name:        "valid rule without comment should be accepted",
			args:        []string{"-t", "nat", "-A", "INPUT", "-p", "tcp", "-j", "ACCEPT"},
			expectError: false,
		},
		{
			name:        "rule with other -m modules should be accepted",
			args:        []string{"-t", "nat", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED"},
			expectError: false,
		},
		{
			name:        "rule with multiple -m modules but no comment should be accepted",
			args:        []string{"-t", "nat", "-A", "INPUT", "-m", "tcp", "-m", "state", "--state", "NEW"},
			expectError: false,
		},
		{
			name:        "word comment in other contexts should be accepted",
			args:        []string{"-t", "nat", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", "comment-test"},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := deps.executeXTables(logger, constants.IPTables, mockVersion, true, nil, tc.args...)

			if tc.expectError {
				assert.Error(t, err)
				if err != nil {
					assert.Equal(t, strings.Contains(err.Error(), tc.errorText), true, "Expected error message to contain: %s, got: %v", tc.errorText, err.Error())
				}
			} else {
				// Note: These tests may fail with actual iptables execution errors since we're not mocking the exec.Command
				// But they should NOT fail with our comment prevention error
				if err != nil {
					assert.Equal(t, strings.Contains(err.Error(), "iptables comment flags are not allowed"), false,
						"Should not fail due to comment prevention, but got: %v", err.Error())
				}
			}
		})
	}
}
