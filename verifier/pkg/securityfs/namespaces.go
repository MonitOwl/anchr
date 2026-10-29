package securityfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MinContainerIDPrefix is the shortest prefix of a container ID a namespace is
// matched by. The kernel module names a namespace after the cgroup of the
// container, truncated to fit its namespace ID buffer, so it may hold only a
// prefix of the container ID.
const MinContainerIDPrefix = 32

// cgroupPrefixes are the prefixes container runtimes add to the container ID
// in the cgroup name, e.g. "cri-containerd-<id>.scope" with the systemd cgroup
// driver. With the cgroupfs driver the cgroup name is the container ID.
var cgroupPrefixes = []string{"cri-containerd-", "crio-", "docker-", "libpod-"}

// ErrNoMeasurementList is returned when the kernel module recorded no measurement list for a container.
var ErrNoMeasurementList = errors.New("no measurement list")

// ContainerID returns the container ID, possibly truncated, in the name of a
// namespace, i.e. the cgroup name of the container.
func ContainerID(namespace string) string {
	for _, prefix := range cgroupPrefixes {
		if id, ok := strings.CutPrefix(namespace, prefix); ok {
			namespace = id
			break
		}
	}
	// container IDs are hexadecimal, so the suffix starts at the first dot, e.g. ".scope".
	if i := strings.IndexByte(namespace, '.'); i >= 0 {
		namespace = namespace[:i]
	}
	return namespace
}

// FindContainerMeasurementList returns the path of the measurement list of the
// container with the given ID, among the namespaces in [ContainerMeasurementDir].
func FindContainerMeasurementList(containerID string) (string, error) {
	return FindMeasurementList(ContainerMeasurementDir, containerID)
}

// FindMeasurementList returns the path of the measurement list of the
// container with the given ID, among the namespaces in dir.
//
// A namespace matches when its [ContainerID] is a prefix of containerID at
// least [MinContainerIDPrefix] long. It returns an error wrapping
// [ErrNoMeasurementList] when no namespace matches, and an error when more
// than one does.
func FindMeasurementList(dir, containerID string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read namespaces: %w", err)
	}

	match := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := ContainerID(entry.Name())
		if len(id) < MinContainerIDPrefix || !strings.HasPrefix(containerID, id) {
			continue
		}
		if match != "" {
			return "", fmt.Errorf("namespaces %s and %s both match container %s", match, entry.Name(), containerID)
		}
		match = entry.Name()
	}
	if match == "" {
		return "", fmt.Errorf("%w for container %s", ErrNoMeasurementList, containerID)
	}
	return filepath.Join(dir, match, "measurements"), nil
}
