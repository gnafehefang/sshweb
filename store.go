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
	"unicode/utf8"

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
	adminHash string // 管理密码的 Argon2id 哈希（PHC 格式）
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

type storeOptions struct {
	EnableSSH       bool
	InitialPassword string // 仅在库里还没有管理密码时使用
}

func loadStore(dir string, opt storeOptions) (*Store, error) {
	enableSSH := opt.EnableSSH
	if err := checkLegacyFiles(dir); err != nil {
		return nil, err
	}
	db, err := openDB(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dir: dir, Players: map[string]*FarmPlayer{}}
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

	if err := s.initAdminPassword(enableSSH, opt.InitialPassword); err != nil {
		return fail(err)
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
	// 旧版明文查看密码：转换为哈希后清空
	for _, pr := range s.ProbeList {
		if pr.ViewPass == "" {
			continue
		}
		h, err := hashPassword(pr.ViewPass, viewArgon)
		if err != nil {
			return fail(err)
		}
		pr.ViewPassHash, pr.ViewPass = h, ""
		if err := upsertJSON(db, "probes", "id", pr.ID, pr); err != nil {
			return fail(err)
		}
	}

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

// maxPlayers 持久化的游客档案上限；超出后新访客只拿到不落盘的临时档案
var maxPlayers = 5000

func (s *Store) GetOrCreatePlayer(ip string) *FarmPlayer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Players == nil {
		s.Players = map[string]*FarmPlayer{}
	}
	if p, ok := s.Players[ip]; ok {
		return p
	}
	if len(s.Players) >= maxPlayers {
		b := make([]byte, 2)
		crand.Read(b)
		return &FarmPlayer{ID: newID()[:10], Name: fmt.Sprintf("访客-%x", b), IP: ip}
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

// 探针读取一律返回副本：修改只能经 UpdateProbe 等方法，避免与并发读写冲突

func cloneProbe(p *Probe) *Probe {
	c := *p
	return &c
}

func (s *Store) Probes() []*Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Probe, len(s.ProbeList))
	for i, p := range s.ProbeList {
		out[i] = cloneProbe(p)
	}
	return out
}

var errProbeNotFound = errors.New("探针不存在")

// UpdateProbe 在副本上修改，写库成功后再替换内存中的记录
func (s *Store) UpdateProbe(id string, fn func(*Probe) error) (*Probe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.ProbeList {
		if p.ID != id {
			continue
		}
		next := cloneProbe(p)
		if err := fn(next); err != nil {
			return nil, err
		}
		if err := upsertJSON(s.db, "probes", "id", next.ID, next); err != nil {
			return nil, err
		}
		s.ProbeList[i] = next
		return cloneProbe(next), nil
	}
	return nil, errProbeNotFound
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
			return cloneProbe(v)
		}
	}
	return nil
}

func (s *Store) ProbeByID(id string) *Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.ProbeList {
		if v.ID == id {
			return cloneProbe(v)
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

// initAdminPassword 管理密码只保存 Argon2id 哈希（meta.admin_pw）。
//   - 旧版明文 meta.password：探针模式下视为旧数据卷，拒绝启动；SSH 模式下转成哈希后删除
//   - 首次启动必须提供至少 12 位的初始密码，不再有默认密码
func (s *Store) initAdminPassword(enableSSH bool, initial string) error {
	hash, _ := s.metaGet("admin_pw")
	legacy, _ := s.metaGet("password")
	if legacy != "" {
		if !enableSSH {
			return errors.New("数据库中存在旧版明文管理密码，说明这是旧版数据卷。探针模式不使用旧数据：请改用全新的数据卷")
		}
		if hash == "" {
			h, err := hashPassword(legacy, adminArgon)
			if err != nil {
				return err
			}
			if err := s.metaSet("admin_pw", h); err != nil {
				return err
			}
			hash = h
		}
		if _, err := s.db.Exec("DELETE FROM meta WHERE k='password'"); err != nil {
			return err
		}
		log.Printf("[store] 已把旧版明文管理密码转换为哈希。旧数据库文件、WAL 与备份中可能仍有明文残留，建议尽快修改管理密码")
	}
	if hash == "" {
		if utf8.RuneCountInString(initial) < minAdminPasswordLen {
			return fmt.Errorf("首次启动必须通过 SSHWEB_PASSWORD 设置管理密码（至少 %d 位）", minAdminPasswordLen)
		}
		h, err := hashPassword(initial, adminArgon)
		if err != nil {
			return err
		}
		if err := s.metaSet("admin_pw", h); err != nil {
			return err
		}
		hash = h
		log.Printf("[store] 管理密码已设置；可以从部署配置中删除 SSHWEB_PASSWORD")
	} else if initial != "" {
		log.Printf("[store] 已存在管理密码，忽略 SSHWEB_PASSWORD；请从部署配置中删除该变量")
	}
	s.adminHash = hash
	return nil
}

func (s *Store) AdminHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adminHash
}

func (s *Store) SetAdminHash(h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.metaSet("admin_pw", h); err != nil {
		return err
	}
	s.adminHash = h
	return nil
}

func (s *Store) Close() {
	if s.db != nil {
		s.db.Close()
	}
}
