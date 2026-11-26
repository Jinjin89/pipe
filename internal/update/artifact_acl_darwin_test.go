// SPDX-License-Identifier: GPL-3.0-or-later

package update

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStageDarwinRejectsWriteACL(t *testing.T) {
	for _, location := range []string{"stage", "ancestor"} {
		t.Run(location, func(t *testing.T) {
			ancestor := filepath.Join(updateTestDir(t), "ancestor")
			base := filepath.Join(ancestor, "updates")
			stage := filepath.Join(base, "stage")
			if err := privateDir(stage); err != nil {
				t.Fatal(err)
			}
			target := stage
			if location == "ancestor" {
				target = ancestor
			}
			if out, err := exec.Command("/bin/chmod", "+a", "everyone deny delete", target).CombinedOutput(); err != nil {
				t.Fatalf("set deny ACL: %v: %s", err, out)
			}
			t.Cleanup(func() {
				if out, err := exec.Command("/bin/chmod", "-N", target).CombinedOutput(); err != nil {
					t.Errorf("clear fixture ACL: %v: %s", err, out)
				}
			})
			if !protectedStage(base, stage) {
				t.Fatal("a deny-only ACL made the protected stage unavailable")
			}
			if out, err := exec.Command("/bin/chmod", "+a", "everyone allow delete_child", target).CombinedOutput(); err != nil {
				t.Fatalf("set write ACL: %v: %s", err, out)
			}
			if protectedStage(base, stage) {
				t.Fatalf("accepted a non-owner delete grant on the %s", location)
			}
		})
	}
}
