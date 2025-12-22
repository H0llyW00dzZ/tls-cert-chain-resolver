// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

package posix

import (
	"os"
	"runtime"
	"testing"
)

// TestGetExecutableName tests the GetExecutableName function for cross-platform compatibility.
func TestGetExecutableName(t *testing.T) {
	// Build test cases based on the current OS
	var tests []struct {
		name     string
		args     []string
		expected string
	}

	// Common test cases for all OS
	commonTests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "Relative path",
			args:     []string{"./myapp"},
			expected: "myapp",
		},
		{
			name:     "Just filename",
			args:     []string{"myapp"},
			expected: "myapp",
		},
		{
			name:     "Empty args",
			args:     []string{},
			expected: "x509-cert-chain-resolver",
		},
		{
			name:     "Empty first arg",
			args:     []string{""},
			expected: "x509-cert-chain-resolver",
		},
	}

	tests = append(tests, commonTests...)

	// OS-specific test cases
	switch runtime.GOOS {
	case "windows":
		windowsTests := []struct {
			name     string
			args     []string
			expected string
		}{
			{
				name:     "Windows absolute path with .exe",
				args:     []string{"C:\\Program Files\\myapp.exe"},
				expected: "myapp",
			},
			{
				name:     "Windows absolute path without .exe",
				args:     []string{"C:\\Program Files\\myapp"},
				expected: "myapp",
			},
			{
				name:     "Windows path with backslashes",
				args:     []string{"C:\\Users\\user\\bin\\myapp.exe"},
				expected: "myapp",
			},
			// This is how GetExecutableName is robust.
			{
				name:     "Test with foreign windows path separators",
				args:     []string{"C:\\windows\\style\\path\\on\\unix\\system.exe"},
				expected: "system",
			},
			{
				name:     "Very long Windows path with 100+ characters",
				args:     []string{"C:\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft PowerPoint\\Presentation Extensions\\PowerPoint.Presentation.8\\powerpoint.exe"},
				expected: "powerpoint",
			},
			{
				name:     "Extremely long Windows path with nested directories",
				args:     []string{"C:\\Users\\VeryLongUserNameThatExceedsNormalLimits\\AppData\\Local\\Microsoft\\WindowsApps\\Microsoft.WindowsTerminal_8wekyb3d8bbwe\\WindowsTerminal.exe"},
				expected: "WindowsTerminal",
			},
		}
		tests = append(tests, windowsTests...)

	default: // Unix-like systems (linux, darwin, etc.)
		unixTests := []struct {
			name     string
			args     []string
			expected string
		}{
			{
				name:     "Unix absolute path",
				args:     []string{"/usr/local/bin/myapp"},
				expected: "myapp",
			},
			{
				name:     "Unix system path",
				args:     []string{"/bin/ls"},
				expected: "ls",
			},
			{
				name:     "Unix home path",
				args:     []string{"/home/user/bin/myapp"},
				expected: "myapp",
			},
		}
		tests = append(tests, unixTests...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args
			origArgs := os.Args

			// Set test args
			os.Args = tt.args

			// Restore args after test
			defer func() {
				os.Args = origArgs
			}()

			result := GetExecutableName()
			t.Logf("Input: %q → Output: %q (Expected: %q)", tt.args, result, tt.expected)
			if result != tt.expected {
				t.Errorf("GetExecutableName() = %q, want %q", result, tt.expected)
			}
		})
	}
}
