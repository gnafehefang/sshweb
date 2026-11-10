package main

// skill.go — AI Skill 建造系统：
//   API Key 管理（存 SQLite）+ POST /api/skill/blocks 批量建造 + POST /api/skill/player 控制角色
//   + GET /api/skill/state 查询状态。方块操作走 gameHub WS 广播路径，网页端实时可见。
//   限速：每 key 每秒 2000 ops（令牌桶）。

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------- API Key 存储 ----------------
// 库里只存 key 的哈希与前缀；完整 key 只在创建时返回一次。

type APIKey struct {
	ID        string `json:"id"`
	Prefix    string `json:"prefix"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

const apiKeySchema = `CREATE TABLE IF NOT EXISTS apikeys_v2(
	id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL, name TEXT, created_at TEXT)`

func apiKeyHash(key string) string {
	h := sha256.Sum256([]byte("sshweb/apikey/v1|" + key))
	return hex.EncodeToString(h[:])
}

func apiKeyPrefix(key string) string {
	if len(key) > 10 {
		return key[:10]
	}
	return key
}

// migrateAPIKeys 建新表，并把旧表中的明文 key 转成哈希后删除
func (s *Store) migrateAPIKeys() error {
	if _, err := s.db.Exec(apiKeySchema); err != nil {
		return err
	}
	rows, err := s.db.Query("SELECT key,name,created_at FROM apikeys")
	if err != nil {
		return err
	}
	type old struct{ key, name, created string }
	var olds []old
	for rows.Next() {
		var o old
		var name, created sql.NullString
		if rows.Scan(&o.key, &name, &created) == nil {
			o.name, o.created = name.String, created.String
			olds = append(olds, o)
		}
	}
	rows.Close()
	for _, o := range olds {
		if _, err := s.db.Exec("INSERT OR IGNORE INTO apikeys_v2(id,hash,prefix,name,created_at) VALUES(?,?,?,?,?)",
			newID(), apiKeyHash(o.key), apiKeyPrefix(o.key), o.name, o.created); err != nil {
			return err
		}
		if _, err := s.db.Exec("DELETE FROM apikeys WHERE key=?", o.key); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) APIKeys() []APIKey {
	rows, err := s.db.Query("SELECT id,prefix,name,created_at FROM apikeys_v2 ORDER BY created_at")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var name, created sql.NullString
		if rows.Scan(&k.ID, &k.Prefix, &name, &created) == nil {
			k.Name, k.CreatedAt = name.String, created.String
			out = append(out, k)
		}
	}
	return out
}

// AddAPIKey 生成新 key，返回元数据与完整 key（只此一次）
func (s *Store) AddAPIKey(name string) (APIKey, string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return APIKey{}, "", err
	}
	key := "sw_" + hex.EncodeToString(b)
	k := APIKey{ID: newID(), Prefix: apiKeyPrefix(key), Name: name, CreatedAt: time.Now().Format(time.RFC3339)}
	_, err := s.db.Exec("INSERT INTO apikeys_v2(id,hash,prefix,name,created_at) VALUES(?,?,?,?,?)",
		k.ID, apiKeyHash(key), k.Prefix, k.Name, k.CreatedAt)
	return k, key, err
}

func (s *Store) DeleteAPIKey(id string) {
	s.db.Exec("DELETE FROM apikeys_v2 WHERE id=?", id)
}

// APIKeyID 按哈希查找 key，返回其 ID（用于限流分桶）
func (s *Store) APIKeyID(key string) (string, bool) {
	if !strings.HasPrefix(key, "sw_") || len(key) > 128 {
		return "", false
	}
	var id string
	if err := s.db.QueryRow("SELECT id FROM apikeys_v2 WHERE hash=?", apiKeyHash(key)).Scan(&id); err != nil {
		return "", false
	}
	return id, true
}

// ---------------- 限速（每 key 2000 ops/s 令牌桶） ----------------

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	rlRate  = 2000.0 // ops/秒
	rlBurst = 2000.0
)

func (r *rateLimiter) take(key string, n int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = map[string]*bucket{}
	}
	b, ok := r.buckets[key]
	now := time.Now()
	if !ok {
		b = &bucket{tokens: rlBurst, last: now}
		r.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rlRate
	b.last = now
	if b.tokens > rlBurst {
		b.tokens = rlBurst
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// ---------------- Skill HTTP API ----------------

func (a *App) skillAuth(r *http.Request) (string, bool) {
	return a.store.APIKeyID(r.Header.Get("X-API-Key"))
}

func (a *App) skillGuard(w http.ResponseWriter, r *http.Request) (string, bool) {
	key, ok := a.skillAuth(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "invalid or missing X-API-Key"})
		return "", false
	}
	return key, true
}

// POST /api/skill/blocks — body: {"ops":[{"op":"add|remove","x":0,"y":0,"z":0,"type":"dirt"}]}
func (a *App) handleSkillBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	key, ok := a.skillGuard(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "read body failed"})
		return
	}
	var generic struct {
		Ops []map[string]any `json:"ops"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil || generic.Ops == nil {
		writeJSON(w, 400, map[string]string{"error": "bad json: need {\"ops\":[...]}"})
		return
	}
	if len(generic.Ops) > 20000 {
		writeJSON(w, 413, map[string]string{"error": "too many ops (max 20000 per request)"})
		return
	}
	if !a.game.limiter.take(key, len(generic.Ops)) {
		writeJSON(w, 429, map[string]string{"error": "rate limit: 2000 ops/s per key"})
		return
	}
	applied, rejected := a.game.applySkillOps(generic.Ops)
	writeJSON(w, 200, map[string]any{"ok": true, "applied": applied, "rejected": rejected, "limit": "2000 ops/s"})
}

// POST /api/skill/player — body: {"x":0,"y":0,"z":0,"yaw":0,"pitch":0,"flying":true,"id":"可选玩家id"}
func (a *App) handleSkillPlayer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := a.skillGuard(w, r); !ok {
		return
	}
	var body struct {
		ID     string   `json:"id"`
		X      *float64 `json:"x"`
		Y      *float64 `json:"y"`
		Z      *float64 `json:"z"`
		Yaw    *float64 `json:"yaw"`
		Pitch  *float64 `json:"pitch"`
		Flying *bool    `json:"flying"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	res := a.game.controlPlayer(body.ID, body.X, body.Y, body.Z, body.Yaw, body.Pitch, body.Flying)
	if !res {
		writeJSON(w, 404, map[string]string{"error": "player not found (need online player id, see /api/skill/state)"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/skill/state — 地图尺寸、材质列表、在线玩家
func (a *App) handleSkillState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := a.skillGuard(w, r); !ok {
		return
	}
	a.game.mu.Lock()
	players := make([]map[string]any, 0, len(a.game.clients))
	for c := range a.game.clients {
		players = append(players, map[string]any{
			"id": c.ID, "name": c.Name, "admin": c.Admin,
			"x": c.X, "z": c.Z, "ry": c.RY, "flying": c.Flying,
		})
	}
	a.game.mu.Unlock()
	mats := []string{}
	for t := range validBlockTypes {
		mats = append(mats, t)
	}
	for i := 1; i <= 7; i++ {
		mats = append(mats, fmt.Sprintf("note%d", i))
	}
	writeJSON(w, 200, map[string]any{
		"version":   version,
		"map":       map[string]any{"groundHalf": 78, "buildRangeXZ": []int{-80, 80}, "buildRangeY": []int{0, 64}},
		"materials": mats,
		"players":   players,
		"blocks":    a.store.BlockCount(),
	})
}

// ---------------- API Key 管理（管理员） ----------------

func (a *App) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := a.store.APIKeys()
		if keys == nil {
			keys = []APIKey{}
		}
		writeJSON(w, 200, keys)
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body)
		name := strings.TrimSpace(body.Name)
		if name == "" {
			name = "skill"
		}
		if len([]rune(name)) > 32 {
			writeJSON(w, 400, map[string]string{"error": "名称太长"})
			return
		}
		k, full, err := a.store.AddAPIKey(name)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "保存失败"})
			return
		}
		// 完整 key 只在创建时返回一次，库里只存哈希
		writeJSON(w, 200, map[string]any{"ok": true, "id": k.ID, "key": full, "name": k.Name, "createdAt": k.CreatedAt})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSON(w, 400, map[string]string{"error": "need id"})
			return
		}
		a.store.DeleteAPIKey(id)
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

// ---------------- gameHub 侧执行 ----------------

// applySkillOps 批量执行方块操作（写 SQLite + WS 广播）
func (h *gameHub) applySkillOps(ops []map[string]any) (applied, rejected int) {
	msgs := make([]map[string]any, 0, len(ops))
	for _, op := range ops {
		kind, _ := op["op"].(string)
		x, y, z := int(f64(op["x"])), int(f64(op["y"])), int(f64(op["z"]))
		if x < -80 || x > 80 || y < 0 || y > 64 || z < -80 || z > 80 {
			rejected++
			continue
		}
		key := fmt.Sprintf("%d,%d,%d", x, y, z)
		switch kind {
		case "add":
			typ, _ := op["type"].(string)
			if !isValidBlockType(typ) {
				rejected++
				continue
			}
			h.store.SetBlock(key, typ)
			msgs = append(msgs, map[string]any{"t": "block", "op": "add", "x": x, "y": y, "z": z, "type": typ, "by": "skill"})
			applied++
		case "remove", "del":
			h.store.SetBlock(key, "-")
			msgs = append(msgs, map[string]any{"t": "block", "op": "del", "x": x, "y": y, "z": z, "type": "", "by": "skill"})
			applied++
		default:
			rejected++
		}
	}
	// 合并广播：批量太大时按 500 一组分帧发，避免慢消费者全丢
	for i := 0; i < len(msgs); i += 500 {
		end := i + 500
		if end > len(msgs) {
			end = len(msgs)
		}
		h.broadcast(map[string]any{"t": "blocks", "ops": msgs[i:end]}, nil)
	}
	return applied, rejected
}

// controlPlayer 通过 skill API 控制在线角色
func (h *gameHub) controlPlayer(id string, x, y, z, yaw, pitch *float64, flying *bool) bool {
	h.mu.Lock()
	var target *gameClient
	for c := range h.clients {
		if id == "" || c.ID == id {
			target = c
			if id != "" {
				break
			}
		}
	}
	if target == nil {
		h.mu.Unlock()
		return false
	}
	if x != nil {
		target.X = *x
	}
	if z != nil {
		target.Z = *z
	}
	if y != nil {
		target.Y = *y
	}
	if yaw != nil {
		target.RY = *yaw
	}
	if flying != nil {
		target.Flying = *flying
	}
	c := target
	h.mu.Unlock()
	c.sendMsg(map[string]any{
		"t": "skillMove",
		"x": c.X, "y": c.Y, "z": c.Z, "ry": c.RY,
		"pitch": pitchValue(pitch), "flying": c.Flying,
	})
	return true
}

func pitchValue(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}
