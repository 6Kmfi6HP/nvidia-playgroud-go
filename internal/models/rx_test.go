package models

import "testing"

func TestRegexOnKnown(t *testing.T) {
	s := `\"nvcfFunctionId\":\"1586112a-925c-48af-8631-7c815dbd749c\"`
	m := fnIDRe.FindStringSubmatch(s)
	if m == nil || m[1] != "1586112a-925c-48af-8631-7c815dbd749c" {
		t.Fatalf("no match: %v", m)
	}
	ns := `\"namespace\":\"qc69jvmznzxy\"`
	if n := nsRe.FindStringSubmatch(ns); n == nil || n[1] != "qc69jvmznzxy" {
		t.Fatalf("ns no match: %v", n)
	}
}
