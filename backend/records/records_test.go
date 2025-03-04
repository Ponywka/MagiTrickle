package records

import (
	"bytes"
	"slices"
	"testing"
	"time"
)

func TestLoop(t *testing.T) {
	r := New()
	r.AddAliasRecord("1", "2", 60)
	r.AddAliasRecord("2", "1", 60)
	if r.GetIPRecords("1") != nil {
		t.Fatal("loop detected")
	}
	if r.GetIPRecords("2") != nil {
		t.Fatal("loop detected")
	}
}

func TestCName(t *testing.T) {
	r := New()
	r.AddIPRecord("example.com", []byte{1, 2, 3, 4}, 60)
	r.AddAliasRecord("gateway.example.com", "example.com", 60)
	records := r.GetIPRecords("gateway.example.com")
	if records == nil {
		t.Fatal("no records")
	}
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("cname mismatch")
	}
}

func TestA(t *testing.T) {
	r := New()
	r.AddIPRecord("example.com", []byte{1, 2, 3, 4}, 60)
	records := r.GetIPRecords("example.com")
	if records == nil {
		t.Fatal("no records")
	}
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("cname mismatch")
	}
}

func TestDeprecated(t *testing.T) {
	r := New()
	r.AddIPRecord("example.com", []byte{1, 2, 3, 4}, 0)
	time.Sleep(time.Second)
	records := r.GetIPRecords("example.com")
	if records != nil {
		t.Fatal("deprecated records")
	}
}

func TestNotExistedA(t *testing.T) {
	r := New()
	records := r.GetIPRecords("example.com")
	if records != nil {
		t.Fatal("not existed records")
	}
}

func TestNotExistedCNameAlias(t *testing.T) {
	r := New()
	r.AddAliasRecord("gateway.example.com", "example.com", 60)
	records := r.GetIPRecords("gateway.example.com")
	if records != nil {
		t.Fatal("not existed records")
	}
}

func TestReplacing(t *testing.T) {
	r := New()
	r.AddAliasRecord("gateway.example.com", "example.com", 60)
	r.AddIPRecord("gateway.example.com", []byte{1, 2, 3, 4}, 60)
	records := r.GetIPRecords("gateway.example.com")
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("mismatch")
	}
}

func TestAliases(t *testing.T) {
	r := New()
	r.AddIPRecord("1", []byte{1, 2, 3, 4}, 60)
	r.AddAliasRecord("2", "1", 60)
	r.AddAliasRecord("3", "2", 60)
	r.AddAliasRecord("4", "2", 60)
	r.AddAliasRecord("5", "1", 60)
	aliases := r.GetAliases("1")
	if aliases == nil {
		t.Fatal("no aliases")
	}
	if !slices.Contains(aliases, "1") {
		t.Fatal("no 1")
	}
	if !slices.Contains(aliases, "2") {
		t.Fatal("no 2")
	}
	if !slices.Contains(aliases, "3") {
		t.Fatal("no 3")
	}
	if !slices.Contains(aliases, "4") {
		t.Fatal("no 4")
	}
	if !slices.Contains(aliases, "5") {
		t.Fatal("no 5")
	}
}
