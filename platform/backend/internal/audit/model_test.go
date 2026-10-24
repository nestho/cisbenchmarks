package audit

import "testing"

func TestLoadSample(t *testing.T) {
	bm, err := Load("../../../audits/cis-apache-2.4.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bm.ID != "cis-apache-2.4" {
		t.Fatalf("bad id %s", bm.ID)
	}
	if len(bm.Controls) != 2 {
		t.Fatalf("controls %d", len(bm.Controls))
	}
}