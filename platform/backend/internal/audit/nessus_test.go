package audit

import "testing"

func TestLoadNessus(t *testing.T) {
	bm, err := LoadNessus("/tmp/scratchpad/tenable-audit/cve-2022-41040_cve-2022-41082/cve-2022-41040_cve-2022-41082.audit")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("id=%s title=%s controls=%d", bm.ID, bm.Title, len(bm.Controls))
	if len(bm.Controls) == 0 {
		t.Fatal("no controls")
	}
}
func TestLoadNessus2(t *testing.T) {
	bm, err := LoadNessus("/tmp/scratchpad/tenable-audit/vmware_plugins_in_vcenter/cve-2021-21985/Linux/CVE-2021-21985_Linux.audit")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("id=%s title=%s controls=%d", bm.ID, bm.Title, len(bm.Controls))
}
