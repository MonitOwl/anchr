package securityfs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MonitOwl/anchr/verifier/pkg/securityfs"
)

const testContainerID = "4f1e8c2d9b7a6e5f4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e"

func TestContainerID(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		testContainerID: testContainerID,
		"cri-containerd-" + testContainerID + ".scope": testContainerID,
		"crio-" + testContainerID + ".scope":           testContainerID,
		"docker-" + testContainerID + ".scope":         testContainerID,
		"libpod-" + testContainerID + ".scope":         testContainerID,
		"cri-containerd-" + testContainerID[:48]:       testContainerID[:48],
		"kubepods-burstable.slice":                     "kubepods-burstable",
		"default":                                      "default",
	}
	for namespace, want := range tests {
		require.Equal(t, want, securityfs.ContainerID(namespace), namespace)
	}
}

// namespacesDir creates a directory of namespaces with the given names.
func namespacesDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0o755))
	}
	return dir
}

func TestFindMeasurementList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
	}{
		{"cgroupfs driver", testContainerID},
		{"systemd driver", "cri-containerd-" + testContainerID + ".scope"},
		{"docker", "docker-" + testContainerID + ".scope"},
		// a cgroup name longer than the namespace ID buffer is truncated.
		{"truncated", "cri-containerd-" + testContainerID[:48]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := namespacesDir(t, "default", "kubepods.slice", tt.namespace)

			got, err := securityfs.FindMeasurementList(dir, testContainerID)
			require.NoError(t, err)
			require.Equal(t, filepath.Join(dir, tt.namespace, "measurements"), got)
		})
	}
}

func TestFindMeasurementListFailures(t *testing.T) {
	t.Parallel()

	other := strings.Repeat("0", 64)
	tests := []struct {
		name       string
		namespaces []string
		want       error
	}{
		{"no namespace", []string{"default", other}, securityfs.ErrNoMeasurementList},
		// a short prefix could match the namespace of another container.
		{
			"prefix too short",
			[]string{testContainerID[:securityfs.MinContainerIDPrefix-1]},
			securityfs.ErrNoMeasurementList,
		},
		{"ambiguous", []string{testContainerID, "cri-containerd-" + testContainerID[:48]}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := namespacesDir(t, tt.namespaces...)

			_, err := securityfs.FindMeasurementList(dir, testContainerID)
			require.Error(t, err)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			}
		})
	}

	_, err := securityfs.FindMeasurementList(filepath.Join(t.TempDir(), "missing"), testContainerID)
	require.Error(t, err)
}
