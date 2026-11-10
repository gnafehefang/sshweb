package main

// store.go — SQLite 持久化存储（modernc.org/sqlite 纯 Go 驱动，无 cgo，单二进制）
//   表：meta(k,v) 元数据 / servers / probes / players(JSON blob)
//       blocks(x,y,z,type) 主键 (x,y,z) / apikeys
//   每条记录单独 upsert / delete，不再整表删除重写。
//
//   本 fork 不再导入旧版 data.json，也删除了从 data.json.migrated 恢复的逻辑：
//   数据目录里出现这类旧文件会直接拒绝启动（其中可能含明文 SSH 凭据）。

import (
	crand "crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type FarmPlayer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Materials int    `json:"materials"`
	LastBonus string `json:"lastBonus,omitempty"`
	IP        string `json:"ip"`
	CreatedAt string `json:"createdAt,omitempty"`
	// 断线重连原地恢复：最后位置
	HasPos bool    `json:"hasPos,omitempty"`
	PX     float64 `json:"px,omitempty"`
	PY     float64 `json:"py,omitempty"`
	PZ     float64 `json:"pz,omitempty"`
}

// ---------------- 数据模型 ----------------

type Server struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	User       string    `json:"user"`
	AuthKind   string    `json:"authKind"` // password | key
	Password   string    `json:"password,omitempty"`
	PrivateKey string    `json:"privateKey,omitempty"`
	KeyPass    string    `json:"keyPass,omitempty"`
	Note       string    `json:"note,omitempty"`
	Region     string    `json:"region,omitempty"`
	LastUsed   time.Time `json:"lastUsed,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

type Store struct {
	mu        sync.Mutex
	db        *sql.DB
	dir       string
	Password  string
	Servers   []*Server
	ProbeList []*Probe
	Players   map[string]*FarmPlayer
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS probes(id TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS players(ip TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS blocks(x INTEGER NOT NULL, y INTEGER NOT NULL, z INTEGER NOT NULL, type TEXT NOT NULL, PRIMARY KEY(x,y,z));
CREATE TABLE IF NOT EXISTS apikeys(key TEXT PRIMARY KEY, name TEXT, created_at TEXT);
`

func openDB(dir string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", filepath.Join(dir, "sshweb.db"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // 单连接避免 SQLITE_BUSY
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// legacyFiles 旧版遗留文件：本 fork 不导入，出现即拒绝启动。
var legacyFiles = []string{"data.json", "data.json.migrated"}

func checkLegacyFiles(dir string) error {
	for _, name := range legacyFiles {
		_, err := os.Stat(filepath.Join(dir, name))
		if err == nil {
			return fmt.Errorf("数据目录中存在旧版文件 %s：本版本不导入旧数据（其中可能含明文凭据）。"+
				"请改用全新的数据卷；旧卷中出现过的凭据请按已泄露处理并轮换", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func loadStore(dir string, enableSSH bool) (*Store, error) {
	if err := checkLegacyFiles(dir); err != nil {
		return nil, err
	}
	db, err := openDB(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dir: dir, Password: "admin888", Players: map[string]*FarmPlayer{}}
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }

	// 探针模式：库里只要有服务器记录就拒绝启动，保证公开实例从不持有 SSH 凭据。
	if !enableSSH {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM servers").Scan(&n); err != nil {
			return fail(err)
		}
		if n > 0 {
			return fail(fmt.Errorf("SSH 功能未开启（SSHWEB_ENABLE_SSH=0），但数据库里有 %d 条服务器记录。"+
				"探针模式不加载任何 SSH 凭据：请改用全新的数据卷", n))
		}
	}

	if v, err := s.metaGet("password"); err == nil && v != "" {
		s.Password = v
	} else {
		if env := os.Getenv("SSHWEB_PASSWORD"); env != "" {
			s.Password = env
		} else {
			log.Printf("[sshweb] 警告: 未设置 SSHWEB_PASSWORD，正在使用默认密码 admin888，请尽快在界面右上角修改")
		}
		if err := s.metaSet("password", s.Password); err != nil {
			return fail(err)
		}
	}

	if enableSSH {
		rows, err := db.Query("SELECT data FROM servers")
		if err != nil {
			return fail(err)
		}
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				continue
			}
			var sv Server
			if json.Unmarshal([]byte(raw), &sv) == nil {
				s.Servers = append(s.Servers, &sv)
			}
		}
		rows.Close()
	}

	rows2, err := db.Query("SELECT data FROM probes")
	if err != nil {
		return fail(err)
	}
	for rows2.Next() {
		var raw string
		if rows2.Scan(&raw) != nil {
			continue
		}
		var pr Probe
		if json.Unmarshal([]byte(raw), &pr) == nil {
			s.ProbeList = append(s.ProbeList, &pr)
		}
	}
	rows2.Close()

	rows3, err := db.Query("SELECT ip, data FROM players")
	if err != nil {
		return fail(err)
	}
	for rows3.Next() {
		var ip, raw string
		if rows3.Scan(&ip, &raw) != nil {
			continue
		}
		var p FarmPlayer
		if json.Unmarshal([]byte(raw), &p) == nil {
			s.Players[ip] = &p
		}
	}
	rows3.Close()
	return s, nil
}

func (s *Store) metaGet(k string) (string, error) {
	var v string
	err := s.db.QueryRow("SELECT v FROM meta WHERE k=?", k).Scan(&v)
	return v, err
}

func (s *Store) metaSet(k, v string) error {
	_, err := s.db.Exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v)
	return err
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// upsertJSON 行级写入（table/keyCol 只来自代码常量）
func upsertJSON(ex execer, table, keyCol, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = ex.Exec("INSERT INTO "+table+"("+keyCol+",data) VALUES(?,?) ON CONFLICT("+keyCol+") DO UPDATE SET data=excluded.data", key, string(b))
	return err
}

// ---------------- 方块（直写 SQLite） ----------------

func (s *Store) BlockGet(key string) string {
	var x, y, z int
	if _, err := fmt.Sscanf(key, "%d,%d,%d", &x, &y, &z); err != nil {
		return ""
	}
	var typ string
	err := s.db.QueryRow("SELECT type FROM blocks WHERE x=? AND y=? AND z=?", x, y, z).Scan(&typ)
	if err != nil {
		return ""
	}
	return typ
}

func (s *Store) SetBlock(key, val string) {
	var x, y, z int
	if _, err := fmt.Sscanf(key, "%d,%d,%d", &x, &y, &z); err != nil {
		return
	}
	if val == "" || val == "-" {
		s.db.Exec("DELETE FROM blocks WHERE x=? AND y=? AND z=?", x, y, z)
		return
	}
	s.db.Exec("INSERT OR REPLACE INTO blocks(x,y,z,type) VALUES(?,?,?,?)", x, y, z, val)
}

func (s *Store) BlocksCopy() map[string]string {
	out := map[string]string{}
	rows, err := s.db.Query("SELECT x,y,z,type FROM blocks")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var x, y, z int
		var typ string
		if rows.Scan(&x, &y, &z, &typ) == nil {
			out[fmt.Sprintf("%d,%d,%d", x, y, z)] = typ
		}
	}
	return out
}

// ClearBlocks 清空全部方块（管理员一键清图）
func (s *Store) ClearBlocks() error {
	_, err := s.db.Exec("DELETE FROM blocks")
	return err
}

func (s *Store) BlockCount() int {
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM blocks").Scan(&n)
	return n
}

// ColumnTop 返回某列 (x,z) 最高方块顶面 y（无方块为 0）
func (s *Store) ColumnTop(x, z int) int {
	var top sql.NullInt64
	s.db.QueryRow("SELECT MAX(y)+1 FROM blocks WHERE x=? AND z=?", x, z).Scan(&top)
	if top.Valid {
		return int(top.Int64)
	}
	return 0
}

// ---------------- 玩家 ----------------

func (s *Store) GetOrCreatePlayer(ip string) *FarmPlayer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Players == nil {
		s.Players = map[string]*FarmPlayer{}
	}
	if p, ok := s.Players[ip]; ok {
		return p
	}
	b := make([]byte, 2)
	crand.Read(b)
	p := &FarmPlayer{
		ID:        newID()[:10],
		Name:      fmt.Sprintf("农夫-%x", b),
		Materials: 50,
		IP:        ip,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	s.Players[ip] = p
	if err := upsertJSON(s.db, "players", "ip", ip, p); err != nil {
		log.Printf("[store] 保存玩家失败: %v", err)
	}
	return p
}

func (s *Store) PlayerByIP(ip string) *FarmPlayer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Players == nil {
		return nil
	}
	return s.Players[ip]
}

// UpdatePlayerPos 记录游客最后位置（内存即时；落盘由调用方节流调用 SavePlayer）
func (s *Store) UpdatePlayerPos(ip string, x, y, z float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.Players[ip]; ok && p != nil {
		p.HasPos, p.PX, p.PY, p.PZ = true, x, y, z
	}
}

// RenamePlayer 改名并落盘，返回是否成功
func (s *Store) RenamePlayer(ip, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Players[ip]
	if !ok || p == nil {
		return false
	}
	p.Name = name
	if err := upsertJSON(s.db, "players", "ip", ip, p); err != nil {
		log.Printf("[store] 保存玩家失败: %v", err)
	}
	return true
}

// SavePlayer 把单个玩家的当前快照写入 SQLite
func (s *Store) SavePlayer(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.Players[ip]; ok && p != nil {
		if err := upsertJSON(s.db, "players", "ip", ip, p); err != nil {
			log.Printf("[store] 保存玩家失败: %v", err)
		}
	}
}

// ---------------- 探针 ----------------

func (s *Store) Probes() []*Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Probe, len(s.ProbeList))
	copy(out, s.ProbeList)
	return out
}

func (s *Store) AddProbe(pr *Probe) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := upsertJSON(s.db, "probes", "id", pr.ID, pr); err != nil {
		return err
	}
	s.ProbeList = append(s.ProbeList, pr)
	return nil
}

func (s *Store) DeleteProbe(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM probes WHERE id=?", id); err != nil {
		log.Printf("[store] 删除探针失败: %v", err)
		return
	}
	out := s.ProbeList[:0]
	for _, v := range s.ProbeList {
		if v.ID != id {
			out = append(out, v)
		}
	}
	s.ProbeList = out
}

func (s *Store) ProbeByToken(token string) *Probe {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.ProbeList {
		if v.Token == token {
			return v
		}
	}
	return nil
}

func (s *Store) ProbeByID(id string) *Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.ProbeList {
		if v.ID == id {
			return v
		}
	}
	return nil
}

// ---------------- 服务器 ----------------

func (s *Store) List() []*Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Server, len(s.Servers))
	copy(out, s.Servers)
	return out
}

func (s *Store) Get(id string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.Servers {
		if v.ID == id {
			return v
		}
	}
	return nil
}

func (s *Store) Put(sv *Server) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, v := range s.Servers {
		if v.ID == sv.ID {
			sv.CreatedAt, sv.LastUsed = v.CreatedAt, v.LastUsed
			if err := upsertJSON(s.db, "servers", "id", sv.ID, sv); err != nil {
				return err
			}
			s.Servers[i] = sv
			return nil
		}
	}
	if err := upsertJSON(s.db, "servers", "id", sv.ID, sv); err != nil {
		return err
	}
	s.Servers = append(s.Servers, sv)
	return nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec("DELETE FROM servers WHERE id=?", id); err != nil {
		return err
	}
	out := s.Servers[:0]
	for _, v := range s.Servers {
		if v.ID != id {
			out = append(out, v)
		}
	}
	s.Servers = out
	return nil
}

func (s *Store) Touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.Servers {
		if v.ID == id {
			v.LastUsed = time.Now()
			upsertJSON(s.db, "servers", "id", v.ID, v)
			return
		}
	}
}

func (s *Store) SetPassword(pw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.metaSet("password", pw); err != nil {
		return err
	}
	s.Password = pw
	return nil
}

func (s *Store) Close() {
	if s.db != nil {
		s.db.Close()
	}
}
