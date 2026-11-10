package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 恢复脚本里的必需表清单必须与当前版本实际建出的表和列一致：
// 新增表或列却忘了更新脚本，恢复时就可能放过缺表的备份。
func TestRestoreScriptRequiredSchemaMatchesStore(t *testing.T) {
	raw, err := os.ReadFile("scripts/restore-backup.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^REQUIRED_SCHEMA="([^"]*)"$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("restore-backup.sh 里找不到 REQUIRED_SCHEMA")
	}
	want := map[string]string{}
	for _, spec := range strings.Fields(string(m[1])) {
		name, cols, ok := strings.Cut(spec, ":")
		if !ok || name == "" || cols == "" {
			t.Fatalf("REQUIRED_SCHEMA 条目格式不对：%q", spec)
		}
		want[name] = cols
	}

	s, err := loadStore(t.TempDir(), storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()

	got := map[string]string{}
	for _, tbl := range tables {
		cr, err := s.db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for cr.Next() {
			var c string
			if err := cr.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		cr.Close()
		got[tbl] = strings.Join(cols, ",")
	}

	keys := func(mp map[string]string) []string {
		var ks []string
		for k := range mp {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	if strings.Join(keys(got), " ") != strings.Join(keys(want), " ") {
		t.Fatalf("表清单不一致：数据库 %v，脚本 %v", keys(got), keys(want))
	}
	for tbl, cols := range got {
		if want[tbl] != cols {
			t.Errorf("表 %s 的列不一致：数据库 %s，脚本 %s", tbl, cols, want[tbl])
		}
	}
}
