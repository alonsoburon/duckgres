package server

import (
	"os/exec"
	"strings"
	"testing"
)

// The server package is meant to be importable from another module (an
// embedding host with its own auth, see Config.QueryAuditHook and
// QueryAccessPolicy) without compiling the control plane's Kubernetes client or
// the Trino/OPA integration. Those live in controlplane/ and the trino
// provisioner; keep them out of server's transitive imports.
func TestServerDoesNotImportControlPlaneDependencies(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	forbidden := []string{
		"k8s.io/",
		"sigs.k8s.io/",
		"github.com/posthog/duckgres/controlplane",
		"github.com/posthog/duckgres/duckdbservice",
		"trino",
	}
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == "github.com/posthog/duckgres/duckdbservice/arrowmap" {
			continue // small Arrow type mapping shared with the worker
		}
		for _, bad := range forbidden {
			if strings.Contains(pkg, bad) {
				t.Errorf("server imports %s (matches %q); keep control-plane dependencies out of server", pkg, bad)
			}
		}
	}
}
