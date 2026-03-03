// host_test.go tests the HTTP handlers, SSE delivery, and JSON-RPC dispatch.
package host

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/yurivish/toolkit/assert"
	"github.com/yurivish/toolkit/pubsub"
)

func extractPort(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Port()
}

// mockProxy implements MCPProxy for testing.
type mockProxy struct {
	callToolResult json.RawMessage
	callToolErr    error
	readResult     json.RawMessage
	readErr        error
}

func (m *mockProxy) CallTool(name string, args json.RawMessage) (json.RawMessage, error) {
	if m.callToolErr != nil {
		return nil, m.callToolErr
	}
	return m.callToolResult, nil
}

func (m *mockProxy) ReadResource(uri string) (json.RawMessage, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return m.readResult, nil
}

// newTestSetupWithProxy creates a test setup with a custom proxy and tools.
func newTestSetupWithProxy(proxy MCPProxy, tools []ToolInfo) (*ViewManager, *HostServer, *httptest.Server, *httptest.Server) {
	vm := NewViewManager(context.Background())
	ps := pubsub.NewPubSub()
	hs := NewHostServer(vm, "0", "0", proxy, func() []ToolInfo { return tools })
	app := NewApp(hs, ps)
	hostServer := httptest.NewServer(app.Mux())
	sandboxServer := httptest.NewServer(hs.SandboxMux())
	hs.hostPort = extractPort(hostServer.URL)
	hs.sandboxPort = extractPort(sandboxServer.URL)
	return vm, hs, hostServer, sandboxServer
}

func newTestSetup() (*ViewManager, *HostServer, *httptest.Server, *httptest.Server) {
	proxy := &mockProxy{
		callToolResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"structuredContent":{"key":"value"}}`),
		readResult:     json.RawMessage(`{"contents":[{"uri":"ui://test","text":"<html>test</html>"}]}`),
	}
	tools := []ToolInfo{
		{Name: "app-tool", Visibility: []string{"app"}},
		{Name: "model-tool", Visibility: []string{"model"}},
		{Name: "both-tool", Visibility: []string{"model", "app"}},
	}
	return newTestSetupWithProxy(proxy, tools)
}

// postRPC sends a JSON-RPC message to the view RPC endpoint and returns the response.
func postRPC(t *testing.T, hostURL, viewID string, msg any) *http.Response {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(hostURL+"/view/"+viewID+"/rpc", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readJSONResponse(t *testing.T, resp *http.Response) jsonrpcMessage {
	t.Helper()
	defer resp.Body.Close()
	var msg jsonrpcMessage
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return msg
}

// =============================================================================
// View page rendering
// =============================================================================

// View page renders with sandbox URL and view ID embedded.
func TestViewPage(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("test1")
	vs.HTML = "<html>hello</html>"

	resp, err := http.Get(hostServer.URL + "/view/test1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should contain the sandbox URL
	if !strings.Contains(bodyStr, sandboxServer.URL+"/sandbox/test1") {
		t.Error("host page does not contain sandbox URL")
	}
	// Should contain the view ID
	if !strings.Contains(bodyStr, "test1") {
		t.Error("host page does not contain view ID")
	}
}

// View page returns 404 for non-existent view.
func TestViewPageNotFound(t *testing.T) {
	_, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	resp, err := http.Get(hostServer.URL + "/view/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// =============================================================================
// SSE delivery
// =============================================================================

// SSE endpoint delivers JSON-RPC messages to the browser as text/event-stream.
func TestSSE(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("sse-test")

	// Start SSE connection in background
	client := &http.Client{Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", hostServer.URL+"/view/sse-test/sse", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, resp.Header.Get("Content-Type"), "text/event-stream")

	// Send a message through the SSE channel
	testMsg := jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "test/notification",
		Params:  map[string]any{"hello": "world"},
	}
	vs.sendSSE(testMsg)

	// Read SSE events
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			data := after
			var msg jsonrpcMessage
			if err := json.Unmarshal([]byte(data), &msg); err != nil {
				t.Fatalf("failed to parse SSE data: %v", err)
			}
			assert.Equal(t, msg.Method, "test/notification")
			return // success
		}
	}
	t.Error("did not receive SSE event")
}

// =============================================================================
// JSON-RPC dispatch
// =============================================================================

// sandbox-proxy-ready triggers sandbox-resource-ready with HTML content via SSE.
func TestRPCSandboxProxyReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("ready-test")
		vs.HTML = "<html>view content</html>"

		// Send sandbox-proxy-ready notification
		resp := postRPC(t, hostServer.URL, "ready-test", jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/sandbox-proxy-ready",
		})
		resp.Body.Close()

		if resp.StatusCode != 204 {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}

		// The handler should have sent sandbox-resource-ready via SSE
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			assert.Equal(t, msg.Method, "ui/notifications/sandbox-resource-ready")
			// Check that html is in params
			var params map[string]any
			json.Unmarshal(msg.Params, &params)
			assert.Equal(t, params["html"], "<html>view content</html>")
		case <-time.After(time.Second):
			t.Error("timeout waiting for SSE message")
		}
	})
}

// Initialized notification triggers tool-input SSE message with tool name and args.
func TestRPCInitializedSendsToolInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("notif-test")
		vs.ToolName = "demo-tool"
		vs.ToolArgs = json.RawMessage(`{"message":"hello"}`)

		// Send initialized notification
		resp := postRPC(t, hostServer.URL, "notif-test", jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/initialized",
		})
		resp.Body.Close()

		if resp.StatusCode != 204 {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}

		// Should have sent tool-input via SSE
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			assert.Equal(t, msg.Method, "ui/notifications/tool-input")
			var params map[string]any
			json.Unmarshal(msg.Params, &params)
			assert.Equal(t, params["toolName"], "demo-tool")
		case <-time.After(time.Second):
			t.Error("timeout waiting for tool-input SSE message")
		}
	})
}

// Initialized notification sends both tool-input and buffered tool-result in order.
func TestRPCInitializedSendsToolResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("result-test")
		vs.ToolName = "demo-tool"
		vs.ToolArgs = json.RawMessage(`{}`)
		vs.ToolResult = json.RawMessage(`{"content":[{"type":"text","text":"done"}]}`)

		// Send initialized notification
		resp := postRPC(t, hostServer.URL, "result-test", jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/initialized",
		})
		resp.Body.Close()

		// Should have sent tool-input AND tool-result via SSE
		var methods []string
		for range 2 {
			select {
			case data := <-vs.SSEChan:
				var msg jsonrpcMessage
				json.Unmarshal(data, &msg)
				methods = append(methods, msg.Method)
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for SSE messages")
			}
		}

		assert.Equal(t, methods[0], "ui/notifications/tool-input")
		assert.Equal(t, methods[1], "ui/notifications/tool-result")
	})
}

// resources/read is proxied to the MCP server and returns the result.
func TestRPCResourcesRead(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("res-test")

	resp := postRPC(t, hostServer.URL, "res-test", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "resources/read",
		Params:  map[string]any{"uri": "ui://test/resource"},
	})
	msg := readJSONResponse(t, resp)
	assert.Nil(t, msg.Error)
	assert.NotNil(t, msg.Result)
}

// ui/request-display-mode returns inline (the only supported mode).
func TestRPCRequestDisplayMode(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("mode-test")

	resp := postRPC(t, hostServer.URL, "mode-test", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ui/request-display-mode",
		Params:  map[string]any{"mode": "fullscreen"},
	})
	msg := readJSONResponse(t, resp)

	var result map[string]any
	json.Unmarshal(msg.Result, &result)
	// Should return inline since that's the only mode we support
	assert.Equal(t, result["mode"], "inline")
}

// Response messages (no method, has id) are delivered to pending request channels.
func TestRPCResponseDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("resp-test")

		// Set up a pending request
		ch := make(chan json.RawMessage, 1)
		vs.PendingRequests.Store("42", ch)

		// Send a response message (no method, has id + result)
		resp := postRPC(t, hostServer.URL, "resp-test", map[string]any{
			"jsonrpc": "2.0",
			"id":      "42",
			"result":  map[string]any{"ok": true},
		})
		resp.Body.Close()

		if resp.StatusCode != 204 {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}

		// The pending request should have received the response
		select {
		case data := <-ch:
			assert.NotNil(t, data)
		case <-time.After(time.Second):
			t.Error("timeout waiting for response delivery")
		}
	})
}

// Unknown RPC method returns JSON-RPC error with code -32601.
func TestRPCUnknownMethod(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("unknown-test")

	resp := postRPC(t, hostServer.URL, "unknown-test", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "nonexistent/method",
	})
	msg := readJSONResponse(t, resp)
	assert.NotNil(t, msg.Error)
}

// =============================================================================
// SendToolResult / SendTeardown
// =============================================================================

// SendToolResult delivers tool-result notification immediately when view is initialized.
func TestSendToolResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("tool-result-test")

		// Mark as initialized
		vs.mu.Lock()
		vs.Initialized = true
		vs.mu.Unlock()

		// Send tool result
		result := json.RawMessage(`{"content":[{"type":"text","text":"result data"}]}`)
		vs.SendToolResult(result)

		// Should have sent notification via SSE
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			assert.Equal(t, msg.Method, "ui/notifications/tool-result")
		case <-time.After(time.Second):
			t.Error("timeout")
		}
	})
}

// SendToolResult buffers result when view is not yet initialized;
// handleInitialized sends tool-input first, then the buffered tool-result.
func TestSendToolResultBeforeInitialized(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("deferred-test")
	vs.ToolName = "test-tool"
	vs.ToolArgs = json.RawMessage(`{}`)

	// Send tool result BEFORE initialized
	result := json.RawMessage(`{"content":[{"type":"text","text":"deferred"}]}`)
	vs.SendToolResult(result)

	// Should NOT have sent anything via SSE yet
	select {
	case <-vs.SSEChan:
		t.Error("should not send tool-result before initialized")
	case <-time.After(50 * time.Millisecond):
		// Good — nothing sent
	}

	// Now send initialized
	resp := postRPC(t, hostServer.URL, "deferred-test", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()

	// Should now get tool-input AND tool-result
	var methods []string
	for range 2 {
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			methods = append(methods, msg.Method)
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	assert.Equal(t, methods[0], "ui/notifications/tool-input")
	assert.Equal(t, methods[1], "ui/notifications/tool-result")
}

// =============================================================================
// extractHTMLAndCSP — resource response parsing
// =============================================================================

// Full resource with HTML text and CSP metadata returns both.
func TestExtractHTMLAndCSP_ValidWithCSP(t *testing.T) {
	raw := json.RawMessage(`{
		"contents": [{
			"text": "<html>hello</html>",
			"_meta": {
				"ui": {
					"csp": {
						"connectDomains": ["https://api.example.com"],
						"resourceDomains": ["https://cdn.example.com"]
					}
				}
			}
		}]
	}`)
	html, csp := extractHTMLAndCSP(raw)
	assert.Equal(t, html, "<html>hello</html>")
	if csp == nil {
		t.Fatal("expected non-nil CSP")
	}
	assert.Equal(t, csp.ConnectDomains, []string{"https://api.example.com"})
	assert.Equal(t, csp.ResourceDomains, []string{"https://cdn.example.com"})
}

// extractHTMLAndCSP returns HTML and nil CSP for simple cases.
func TestExtractHTMLAndCSP(t *testing.T) {
	tests := []struct {
		name     string
		raw      json.RawMessage
		wantHTML string
		wantCSP  bool // false means expect nil
	}{
		{"valid_without_csp", json.RawMessage(`{"contents":[{"text":"<html>no csp</html>"}]}`), "<html>no csp</html>", false},
		{"invalid_json", json.RawMessage(`not json`), "", false},
		{"empty_contents", json.RawMessage(`{"contents":[]}`), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html, csp := extractHTMLAndCSP(tt.raw)
			assert.Equal(t, html, tt.wantHTML)
			if tt.wantCSP && csp == nil {
				t.Error("expected non-nil CSP")
			}
			if !tt.wantCSP && csp != nil {
				t.Errorf("expected nil CSP, got %v", csp)
			}
		})
	}
}

// =============================================================================
// handleIndex — GET /
// =============================================================================

// Index page returns 200 with text/html and lists tool names.
func TestHandleIndex(t *testing.T) {
	_, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	resp, err := http.Get(hostServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html Content-Type, got %s", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "app-tool") {
		t.Error("index page should contain tool name 'app-tool'")
	}
}

// =============================================================================
// CreateToolCall — orchestration logic
// =============================================================================

// Unknown tool name returns error.
func TestCreateToolCall_UnknownTool(t *testing.T) {
	_, hs, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	_, err := hs.CreateToolCall("nonexistent", json.RawMessage(`{}`))
	assert.NotNil(t, err)
}

// Non-UI tool (no ResourceURI) calls tool directly and returns Result.
func TestCreateToolCall_NonUITool(t *testing.T) {
	_, hs, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	res, err := hs.CreateToolCall("app-tool", json.RawMessage(`{"key":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res.ViewURL, "")
	assert.NotNil(t, res.Result)
}

// Non-UI tool propagates CallTool error.
func TestCreateToolCall_NonUITool_Error(t *testing.T) {
	proxy := &mockProxy{callToolErr: errors.New("tool failed")}
	_, hs, hostServer, sandboxServer := newTestSetupWithProxy(proxy, []ToolInfo{{Name: "fail-tool"}})
	defer hostServer.Close()
	defer sandboxServer.Close()

	_, err := hs.CreateToolCall("fail-tool", json.RawMessage(`{}`))
	assert.NotNil(t, err)
}

// UI tool creates a view, returns ViewURL, and delivers async tool result.
func TestCreateToolCall_UITool(t *testing.T) {
	proxy := &mockProxy{
		callToolResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
		readResult:     json.RawMessage(`{"contents":[{"text":"<html>ui</html>"}]}`),
	}
	tools := []ToolInfo{{Name: "ui-tool", ResourceURI: "ui://test"}}
	vm, hs, hostServer, sandboxServer := newTestSetupWithProxy(proxy, tools)
	defer hostServer.Close()
	defer sandboxServer.Close()

	res, err := hs.CreateToolCall("ui-tool", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.ViewURL == "" || !strings.HasPrefix(res.ViewURL, "/view/") {
		t.Errorf("UI tool should return ViewURL starting with /view/, got %q", res.ViewURL)
	}

	// The view should have been created with the fetched HTML
	viewID := strings.TrimPrefix(res.ViewURL, "/view/")
	vs := vm.Get(viewID)
	if vs == nil {
		t.Fatal("view should have been created")
	}
	assert.Equal(t, vs.HTML, "<html>ui</html>")

	// Wait for async tool result delivery
	time.Sleep(50 * time.Millisecond)
	if vs.ToolResult == nil {
		t.Error("tool result should have been delivered asynchronously")
	}
}

// UI tool with ReadResource failure returns error (no view created).
func TestCreateToolCall_UITool_ReadResourceError(t *testing.T) {
	proxy := &mockProxy{readErr: errors.New("resource not found")}
	tools := []ToolInfo{{Name: "ui-tool", ResourceURI: "ui://missing"}}
	_, hs, hostServer, sandboxServer := newTestSetupWithProxy(proxy, tools)
	defer hostServer.Close()
	defer sandboxServer.Close()

	_, err := hs.CreateToolCall("ui-tool", json.RawMessage(`{}`))
	assert.NotNil(t, err)
}

// UI tool with async CallTool failure delivers error result (isError: true) to view.
func TestCreateToolCall_UITool_CallToolError(t *testing.T) {
	proxy := &mockProxy{
		callToolErr: errors.New("tool execution failed"),
		readResult:  json.RawMessage(`{"contents":[{"text":"<html>ui</html>"}]}`),
	}
	tools := []ToolInfo{{Name: "ui-tool", ResourceURI: "ui://test"}}
	vm, hs, hostServer, sandboxServer := newTestSetupWithProxy(proxy, tools)
	defer hostServer.Close()
	defer sandboxServer.Close()

	res, err := hs.CreateToolCall("ui-tool", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err) // CreateToolCall itself shouldn't fail; the error is async
	}

	viewID := strings.TrimPrefix(res.ViewURL, "/view/")
	vs := vm.Get(viewID)

	// Wait for async error result delivery
	time.Sleep(50 * time.Millisecond)
	if vs.ToolResult == nil {
		t.Fatal("error tool result should have been delivered asynchronously")
	}

	var result map[string]any
	json.Unmarshal(vs.ToolResult, &result)
	if result["isError"] != true {
		t.Error("async tool error should set isError: true")
	}
}

// =============================================================================
// View management — NextID, TeardownAll, sendSSE
// =============================================================================

// NextID returns sequential IDs: v0, v1, v2, ...
func TestNextID_Sequential(t *testing.T) {
	vm := NewViewManager(context.Background())
	ids := []string{vm.NextID(), vm.NextID(), vm.NextID()}
	expected := []string{"v0", "v1", "v2"}
	for i, id := range ids {
		assert.Equal(t, id, expected[i])
	}
}

// TeardownAll sends ui/resource-teardown to every active view.
func TestTeardownAll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm := NewViewManager(context.Background())
		views := []*ViewState{vm.Create("a"), vm.Create("b"), vm.Create("c")}

		vm.TeardownAll()

		for _, vs := range views {
			select {
			case data := <-vs.SSEChan:
				var msg jsonrpcMessage
				json.Unmarshal(data, &msg)
				assert.Equal(t, msg.Method, "ui/resource-teardown")
			case <-time.After(time.Second):
				t.Errorf("view %s: timeout waiting for teardown", vs.ID)
			}
		}
	})
}

// sendSSE drops message without panic when channel is full (capacity 64).
func TestSendSSE_ChannelFull(t *testing.T) {
	vm := NewViewManager(context.Background())
	vs := vm.Create("full")

	// Fill the channel (capacity 64)
	for i := range 64 {
		vs.sendSSE(jsonrpcNotification{JSONRPC: "2.0", Method: fmt.Sprintf("msg/%d", i)})
	}

	// One more should be dropped without panic
	err := vs.sendSSE(jsonrpcNotification{JSONRPC: "2.0", Method: "overflow"})
	assert.Nil(t, err)
}

// =============================================================================
// origin helper
// =============================================================================

// origin strips the request port and constructs origin with the given port.
func TestOrigin(t *testing.T) {
	_, hs, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	tests := []struct {
		name string
		host string
		want string
	}{
		{"with_port", "localhost:8080", "http://localhost:9090"},
		{"without_port", "example.com", "http://example.com:9090"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Host: tt.host}
			got := hs.origin(r, "9090")
			assert.Equal(t, got, tt.want)
		})
	}
}

// =============================================================================
// HTTP 404 paths
// =============================================================================

// Non-existent views return 404 across SSE, sandbox, and RPC endpoints.
func TestNotFound(t *testing.T) {
	_, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	tests := []struct {
		name   string
		method string
		url    string
	}{
		{"sse", "GET", hostServer.URL + "/view/nonexistent/sse"},
		{"sandbox", "GET", sandboxServer.URL + "/sandbox/nonexistent"},
		{"rpc", "POST", hostServer.URL + "/view/nonexistent/rpc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *http.Response
			var err error
			if tt.method == "POST" {
				body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
				resp, err = http.Post(tt.url, "application/json", strings.NewReader(body))
			} else {
				resp, err = http.Get(tt.url)
			}
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("expected 404, got %d", resp.StatusCode)
			}
		})
	}
}

// RPC endpoint returns 400 for malformed JSON body.
func TestHandleViewRPC_MalformedJSON(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("badjson")

	resp, err := http.Post(
		hostServer.URL+"/view/badjson/rpc",
		"application/json",
		strings.NewReader("not json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// =============================================================================
// RPC edge cases
// =============================================================================

// Response with unknown pending request ID returns 204 without panic.
func TestHandleViewRPC_ResponseToUnknownPendingRequest(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("unknown-pending")

	resp := postRPC(t, hostServer.URL, "unknown-pending", map[string]any{
		"jsonrpc": "2.0",
		"id":      "999",
		"result":  map[string]any{"ok": true},
	})
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

// resources/read with unparseable params returns JSON-RPC error.
func TestHandleResourcesRead_InvalidParams(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("bad-params")

	resp := postRPC(t, hostServer.URL, "bad-params", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "resources/read",
	})
	msg := readJSONResponse(t, resp)
	assert.NotNil(t, msg.Error)
}

// =============================================================================
// Full RPC lifecycle
// =============================================================================

// slowProxy is a mock that delays CallTool responses, simulating a slow MCP server.
type slowProxy struct {
	delay          time.Duration
	callToolResult json.RawMessage
	readResult     json.RawMessage
}

func (p *slowProxy) CallTool(name string, args json.RawMessage) (json.RawMessage, error) {
	time.Sleep(p.delay)
	return p.callToolResult, nil
}

func (p *slowProxy) ReadResource(uri string) (json.RawMessage, error) {
	return p.readResult, nil
}

// Full browser-like lifecycle completes without hanging:
// sandbox-proxy-ready → ui/initialize → initialized → tools/call.
func TestFullRPCLifecycle(t *testing.T) {
	proxy := &slowProxy{
		delay:          20 * time.Millisecond,
		callToolResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`),
		readResult:     json.RawMessage(`{"contents":[{"text":"<html>ui</html>"}]}`),
	}
	tools := []ToolInfo{
		{Name: "ui-tool", ResourceURI: "ui://test", Visibility: []string{"model", "app"}},
		{Name: "count-words", Visibility: []string{"app"}},
	}
	vm, hs, hostServer, sandboxServer := newTestSetupWithProxy(proxy, tools)
	defer hostServer.Close()
	defer sandboxServer.Close()

	// 1. Create the tool call (as handleCall would) — creates the view
	res, err := hs.CreateToolCall("ui-tool", json.RawMessage(`{"message":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	viewID := strings.TrimPrefix(res.ViewURL, "/view/")
	vs := vm.Get(viewID)
	if vs == nil {
		t.Fatal("view should exist")
	}

	deadline := 100 * time.Millisecond

	// 2. sandbox-proxy-ready → triggers sandbox-resource-ready via SSE
	resp := postRPC(t, hostServer.URL, viewID, jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/sandbox-proxy-ready",
	})
	resp.Body.Close()
	assert.Equal(t, resp.StatusCode, 204)

	select {
	case data := <-vs.SSEChan:
		var msg jsonrpcMessage
		json.Unmarshal(data, &msg)
		assert.Equal(t, msg.Method, "ui/notifications/sandbox-resource-ready")
	case <-time.After(deadline):
		t.Fatal("timeout waiting for sandbox-resource-ready")
	}

	// 3. ui/initialize → returns host capabilities
	resp = postRPC(t, hostServer.URL, viewID, jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ui/initialize",
	})
	msg := readJSONResponse(t, resp)
	assert.Nil(t, msg.Error)
	assert.NotNil(t, msg.Result)

	// 4. initialized → triggers tool-input (and maybe tool-result) via SSE
	resp = postRPC(t, hostServer.URL, viewID, jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()
	assert.Equal(t, resp.StatusCode, 204)

	select {
	case data := <-vs.SSEChan:
		var msg jsonrpcMessage
		json.Unmarshal(data, &msg)
		assert.Equal(t, msg.Method, "ui/notifications/tool-input")
	case <-time.After(deadline):
		t.Fatal("timeout waiting for tool-input")
	}

	// 5. tools/call (nested call from the UI) — must complete within deadline
	done := make(chan struct{})
	go func() {
		resp := postRPC(t, hostServer.URL, viewID, jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      2,
			Method:  "tools/call",
			Params:  map[string]any{"name": "count-words", "arguments": map[string]any{"text": "hello world"}},
		})
		msg := readJSONResponse(t, resp)
		assert.Nil(t, msg.Error)
		assert.NotNil(t, msg.Result)
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(deadline):
		t.Fatal("tools/call hung — RPC did not complete within deadline")
	}
}
