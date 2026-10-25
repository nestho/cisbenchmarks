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

func TestLoadExtractedCISYAML(t *testing.T) {
	bm, err := Load("../../../audits/cis-docker-v1.8.0-sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bm.ID != "cis-docker-benchmark" {
		t.Fatalf("unexpected benchmark id: %s", bm.ID)
	}
	if len(bm.Controls) < 3 {
		t.Fatalf("expected at least 3 controls, got %d", len(bm.Controls))
	}
}