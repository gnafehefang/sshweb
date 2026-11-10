package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRefusesLegacyFiles(t *testing.T) {
	for _, name := range legacyFiles {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"Servers":[{"id":"x","password":"p"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, ssh := range []bool{false, true} {
			if _, err := loadStore(dir, ssh); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("存在 %s 时应拒绝启动 (ssh=%v), got %v", name, ssh, err)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "sshweb.db")); err == nil {
			t.Fatalf("拒绝启动前不应创建数据库")
		}
	}
}

func TestProbeModeRefusesServerRows(t *testing.T) {
	dir := t.TempDir()
	s, err := loadStore(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(&Server{ID: "s1", Name: "n", Host: "h", Port: 22, User: "u", AuthKind: "password", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := loadStore(dir, false); err == nil || !strings.Contains(err.Error(), "服务器记录") {
		t.Fatalf("探针模式遇到服务器记录应拒绝启动, got %v", err)
	}
	s2, err := loadStore(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if len(s2.List()) != 1 {
		t.Fatal("SSH 模式应能加载服务器记录")
	}
}

func TestProbeModeDoesNotLoadServers(t *testing.T) {
	s, err := loadStore(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.List()) != 0 {
		t.Fatal("探针模式不应有服务器")
	}
}

func TestRowLevelPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := loadStore(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	p := s.GetOrCreatePlayer("203.0.113.9")
	s.RenamePlayer("203.0.113.9", "alice")
	s.UpdatePlayerPos("203.0.113.9", 1, 2, 3)
	s.SavePlayer("203.0.113.9")
	if err := s.AddProbe(&Probe{ID: "p1", Name: "n1", Public: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProbe(&Probe{ID: "p2", Name: "n2", Public: true}); err != nil {
		t.Fatal(err)
	}
	s.DeleteProbe("p1")
	s.Close()

	s2, err := loadStore(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	q := s2.PlayerByIP("203.0.113.9")
	if q == nil || q.ID != p.ID || q.Name != "alice" || !q.HasPos || q.PZ != 3 {
		t.Fatalf("玩家未正确持久化: %+v", q)
	}
	if ps := s2.Probes(); len(ps) != 1 || ps[0].ID != "p2" {
		t.Fatalf("探针行级持久化错误: %+v", ps)
	}
}
