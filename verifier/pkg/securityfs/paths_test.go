package securityfs_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MonitOwl/anchr/verifier/pkg/securityfs"
)

func TestCurrentModulePaths(t *testing.T) {
	t.Parallel()
	require.Equal(t, "/sys/kernel/security/anchr/merkle_root_history", securityfs.LeafListPath)
	require.Equal(t, "/sys/kernel/security/anchr/namespaces/default/measurements", securityfs.GlobalMeasurementListPath)
	require.Equal(t, "/sys/kernel/security/anchr/namespaces/example/measurements",
		securityfs.ContainerMeasurementListPath("example"))
}
