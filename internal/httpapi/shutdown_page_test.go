package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestExitPageCanStillStop(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	csrf, body := h.home()
	if !strings.Contains(body, "开始生成") {
		t.Fatalf("idle page missing start: %s", body)
	}
	res := h.c.do(http.MethodPost, "/start", url.Values{"csrf": {csrf}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("start %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	h.runner.Shutdown()
	_, body = h.home()
	if strings.Contains(body, "开始生成") || !strings.Contains(body, ">停止<") || !strings.Contains(body, "正在退出") {
		t.Fatalf("exit page: %s", body)
	}
	res = h.c.do(http.MethodPost, "/stop", url.Values{"csrf": {mustCSRF(t, body)}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "确认停止") {
		t.Fatalf("confirm %d %s", res.StatusCode, body)
	}
	res = h.c.do(http.MethodPost, "/stop", url.Values{"csrf": {mustCSRF(t, body)}, "confirm": {"yes"}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("stop %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	settings, err := h.st.Settings()
	if err != nil || settings.Running {
		t.Fatalf("stop did not persist: %v %+v", err, settings)
	}
	_, body = h.home()
	if strings.Contains(body, "开始生成") || !strings.Contains(body, "已经停止") {
		t.Fatalf("after stop: %s", body)
	}
}
