package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestClientIPTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("172.30.10.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote, xff, xreal, want string
	}{
		{"直连客户端伪造 XFF 被忽略", "203.0.113.5:1234", "1.2.3.4", "", "203.0.113.5"},
		{"直连客户端伪造 X-Real-IP 被忽略", "203.0.113.5:1234", "", "1.2.3.4", "203.0.113.5"},
		{"可信代理覆盖 XFF", "172.30.10.1:999", "198.51.100.7", "", "198.51.100.7"},
		{"可信代理追加：取最右边的不可信地址", "172.30.10.1:999", "6.6.6.6, 198.51.100.7", "", "198.51.100.7"},
		{"跳过多级可信代理", "172.30.10.1:999", "198.51.100.7, 10.1.2.3", "", "198.51.100.7"},
		{"畸形条目之后停止，回退到直连地址", "172.30.10.1:999", "198.51.100.7, garbage", "", "172.30.10.1"},
		{"可信代理仅给 X-Real-IP", "172.30.10.1:999", "", "198.51.100.8", "198.51.100.8"},
		{"IPv4 映射地址归一", "[::ffff:203.0.113.5]:1", "", "", "203.0.113.5"},
		{"IPv6", "[2001:db8::1]:443", "1.2.3.4", "", "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.xreal != "" {
			r.Header.Set("X-Real-IP", c.xreal)
		}
		if got := clientIPFrom(r, trusted); got != c.want {
			t.Errorf("%s: want %s got %s", c.name, c.want, got)
		}
	}
}

func TestKeyedLimiter(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	l := newKeyedLimiter(1, 3, 2)
	l.now = clk.now
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatal("突发额度内应放行")
		}
	}
	if l.allow("a") {
		t.Fatal("超过突发额度应拒绝")
	}
	clk.t = clk.t.Add(time.Second)
	if !l.allow("a") {
		t.Fatal("补充后应放行")
	}
	l.allow("b")
	if l.allow("c") {
		t.Fatal("表满且无可清理项时应拒绝新键")
	}
	clk.t = clk.t.Add(10 * time.Second)
	if !l.allow("c") {
		t.Fatal("旧桶回满后应被清理，新键可进入")
	}
}

func TestGameWSPerIPLimit(t *testing.T) {
	e := newTestEnv(t, false)
	srv := httptest.NewServer(e.public)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/game"
	h := http.Header{}
	h.Set("Origin", testPublic)
	var conns []*websocket.Conn
	for i := 0; i < maxGameConnsPerIP; i++ {
		c, _, err := websocket.DefaultDialer.Dial(url, h)
		if err != nil {
			t.Fatalf("第 %d 个连接应成功: %v", i+1, err)
		}
		conns = append(conns, c)
	}
	_, resp, err := websocket.DefaultDialer.Dial(url, h)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("超出每 IP 连接数应 429, got %v %v", resp, err)
	}
	conns[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, _, err := websocket.DefaultDialer.Dial(url, h)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("关闭一个连接后应能重新连接: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, c := range conns[1:] {
		c.Close()
	}
}

func newTestClient(h *gameHub) *gameClient {
	return &gameClient{ID: "c1", Name: "t", hub: h, send: make(chan []byte, 256),
		msgBucket: newLocalBucket(gameMsgRate, gameMsgBurst), blockBucket: newLocalBucket(gameBlockRate, gameBlockBurst)}
}

func TestExplodeRequiresMinedTNT(t *testing.T) {
	e := newTestEnv(t, false)
	h := e.app.game
	st := e.app.store
	st.SetBlock("10,5,10", "tnt")
	st.SetBlock("11,5,10", "stone")
	c := newTestClient(h)

	h.handle(c, map[string]any{"t": "explode", "x": 11.0, "y": 5.0, "z": 10.0})
	if st.BlockGet("11,5,10") != "stone" {
		t.Fatal("没有挖掉 TNT 时 explode 不应生效")
	}
	h.handle(c, map[string]any{"t": "block", "op": "del", "x": 10.0, "y": 5.0, "z": 10.0})
	h.handle(c, map[string]any{"t": "explode", "x": 30.0, "y": 5.0, "z": 30.0})
	if st.BlockGet("11,5,10") != "stone" {
		t.Fatal("坐标不对应时不应爆炸")
	}
	h.handle(c, map[string]any{"t": "explode", "x": 10.0, "y": 5.0, "z": 10.0})
	if st.BlockGet("11,5,10") != "" {
		t.Fatal("挖掉 TNT 后对应坐标应爆炸")
	}
	st.SetBlock("11,5,10", "stone")
	h.handle(c, map[string]any{"t": "explode", "x": 10.0, "y": 5.0, "z": 10.0})
	if st.BlockGet("11,5,10") != "stone" {
		t.Fatal("一次 TNT 只能引爆一次")
	}
}

func TestPerConnectionMessageLimit(t *testing.T) {
	c := newTestClient(nil)
	allowed := 0
	for i := 0; i < 100; i++ {
		if c.allowMsg("block") {
			allowed++
		}
	}
	if allowed != gameBlockBurst {
		t.Fatalf("方块消息突发上限应为 %d, got %d", gameBlockBurst, allowed)
	}
	c2 := newTestClient(nil)
	allowed = 0
	for i := 0; i < 200; i++ {
		if c2.allowMsg("pos") {
			allowed++
		}
	}
	if allowed != gameMsgBurst {
		t.Fatalf("普通消息突发上限应为 %d, got %d", gameMsgBurst, allowed)
	}
}

func TestPlayerCapGivesEphemeralRecord(t *testing.T) {
	old := maxPlayers
	maxPlayers = 2
	defer func() { maxPlayers = old }()
	s, err := loadStore(t.TempDir(), storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.GetOrCreatePlayer("192.0.2.1")
	s.GetOrCreatePlayer("192.0.2.2")
	p := s.GetOrCreatePlayer("192.0.2.3")
	if p == nil || s.PlayerByIP("192.0.2.3") != nil {
		t.Fatal("超出上限的访客应拿到临时档案且不落盘")
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM players").Scan(&n)
	if n != 2 {
		t.Fatalf("数据库中玩家数应为 2, got %d", n)
	}
}

func TestProbeReportMinInterval(t *testing.T) {
	e := newTestEnv(t, false)
	if err := e.app.store.AddProbe(&Probe{ID: "p1", Token: "tok123", Public: true}); err != nil {
		t.Fatal(err)
	}
	body := `{"hostname":"h\u0007ost","cpu":1}`
	if w := do(e.public, http.MethodPost, "/api/probe/report?t=tok123", body); w.Code != 200 {
		t.Fatalf("首次上报应成功: %d %s", w.Code, w.Body.String())
	}
	if w := do(e.public, http.MethodPost, "/api/probe/report?t=tok123", body); w.Code != http.StatusTooManyRequests {
		t.Fatalf("2 秒内再次上报应 429, got %d", w.Code)
	}
	if st := e.app.probes.get("p1"); st == nil || st.Hostname != "host" || st.IP != "192.0.2.10" {
		t.Fatalf("上报内容应去掉控制字符并记录直连 IP: %+v", st)
	}
}
