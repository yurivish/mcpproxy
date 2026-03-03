// spec_test.go — Tests verifying compliance with SEP-1865 MUST requirements.
//
// Each test is tagged with the spec section and requirement it covers.
// Tests are grouped by the spec section they relate to.

package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/yurivish/toolkit/assert"
)

// drainSSE reads all queued SSE messages from a view state, returning them.
func drainSSE(vs *ViewState, timeout time.Duration) []jsonrpcMessage {
	var msgs []jsonrpcMessage
	for {
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			msgs = append(msgs, msg)
		case <-time.After(timeout):
			return msgs
		}
	}
}

// capturingProxy wraps an MCPProxy to record which tools/resources were called.
type capturingProxy struct {
	inner    MCPProxy
	toolCall chan string
	resRead  chan string
}

func (p *capturingProxy) CallTool(name string, args json.RawMessage) (json.RawMessage, error) {
	if p.toolCall != nil {
		p.toolCall <- name
	}
	return p.inner.CallTool(name, args)
}

func (p *capturingProxy) ReadResource(uri string) (json.RawMessage, error) {
	if p.resRead != nil {
		p.resRead <- uri
	}
	return p.inner.ReadResource(uri)
}

// =============================================================================
// §4.3 UI Resource Format — CSP Enforcement
// =============================================================================

// Spec §4.3: "Host MUST construct CSP headers based on declared domains"
func TestSpec_CSP_ConstructedFromDeclaredDomains(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("csp-declared")
	vs.csp = &ResourceCSP{
		ConnectDomains:  []string{"https://api.example.com"},
		ResourceDomains: []string{"https://cdn.example.com"},
	}

	resp, err := http.Get(sandboxServer.URL + "/sandbox/csp-declared")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self' https://api.example.com") {
		t.Errorf("CSP connect-src does not include declared domain: %s", csp)
	}
	if !strings.Contains(csp, "https://cdn.example.com") {
		t.Errorf("CSP does not include declared resource domain: %s", csp)
	}
}

// Spec §4.3: "If ui.csp is omitted, Host MUST use restrictive default"
// Default MUST include: connect-src 'none' (not 'self')
func TestSpec_CSP_RestrictiveDefaultWhenOmitted(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("csp-nil") // csp field is nil

	resp, err := http.Get(sandboxServer.URL + "/sandbox/csp-nil")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")

	// Spec's required restrictive defaults
	required := []string{
		"default-src 'none'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"media-src 'self' data:",
		"connect-src 'none'",
	}
	for _, r := range required {
		if !strings.Contains(csp, r) {
			t.Errorf("restrictive default CSP missing %q:\n  got: %s", r, csp)
		}
	}
}

// Spec §4.3: "Host MUST NOT allow undeclared domains"
func TestSpec_CSP_MustNotAllowUndeclaredDomains(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("csp-no-leak")
	vs.csp = &ResourceCSP{
		ConnectDomains: []string{"https://allowed.com"},
		// No resourceDomains declared
	}

	resp, err := http.Get(sandboxServer.URL + "/sandbox/csp-no-leak")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")

	// script-src should NOT contain any https:// domains since resourceDomains is empty
	for part := range strings.SplitSeq(csp, "; ") {
		if strings.HasPrefix(part, "script-src ") {
			if strings.Contains(part, "https://") {
				t.Errorf("script-src contains undeclared domain (no resourceDomains set): %s", part)
			}
		}
		// img-src should NOT contain external domains
		if strings.HasPrefix(part, "img-src ") {
			if strings.Contains(part, "https://") {
				t.Errorf("img-src contains undeclared domain: %s", part)
			}
		}
	}

	// connect-src MUST include allowed.com
	if !strings.Contains(csp, "https://allowed.com") {
		t.Errorf("connect-src missing declared domain: %s", csp)
	}
}

// Spec §4.3 CSP: "frame-src 'none'" if frameDomains not provided
func TestSpec_CSP_FrameSrcNoneByDefault(t *testing.T) {
	csp := buildCSP(&ResourceCSP{})
	if !strings.Contains(csp, "frame-src 'none'") {
		t.Errorf("expected frame-src 'none' when frameDomains empty, got: %s", csp)
	}
}

// Spec §4.3 CSP: "base-uri 'self'" if baseUriDomains not provided
func TestSpec_CSP_BaseUriSelfByDefault(t *testing.T) {
	csp := buildCSP(&ResourceCSP{})
	if !strings.Contains(csp, "base-uri 'self'") {
		t.Errorf("expected base-uri 'self' when baseUriDomains empty, got: %s", csp)
	}
}

// Spec §4.3 CSP: "Block dangerous features (object-src 'none')"
func TestSpec_CSP_ObjectSrcNone(t *testing.T) {
	csp := buildCSP(&ResourceCSP{
		ConnectDomains:  []string{"https://example.com"},
		ResourceDomains: []string{"https://cdn.example.com"},
	})
	if !strings.Contains(csp, "object-src 'none'") {
		t.Errorf("CSP missing object-src 'none': %s", csp)
	}
}

// Spec §4.3 CSP: frame-src uses declared frameDomains when provided
func TestSpec_CSP_FrameSrcUsesFrameDomains(t *testing.T) {
	csp := buildCSP(&ResourceCSP{
		FrameDomains: []string{"https://youtube.com", "https://vimeo.com"},
	})
	if strings.Contains(csp, "frame-src 'none'") {
		t.Errorf("frame-src should not be 'none' when frameDomains provided: %s", csp)
	}
	if !strings.Contains(csp, "https://youtube.com") {
		t.Errorf("frame-src missing declared domain: %s", csp)
	}
	if !strings.Contains(csp, "https://vimeo.com") {
		t.Errorf("frame-src missing declared domain: %s", csp)
	}
}

// Spec §4.3 CSP: base-uri uses declared baseUriDomains when provided
func TestSpec_CSP_BaseUriUsesBaseUriDomains(t *testing.T) {
	csp := buildCSP(&ResourceCSP{
		BaseURIDomains: []string{"https://cdn.example.com"},
	})
	if strings.Contains(csp, "base-uri 'self'") {
		t.Errorf("base-uri should not be 'self' when baseUriDomains provided: %s", csp)
	}
	if !strings.Contains(csp, "https://cdn.example.com") {
		t.Errorf("base-uri missing declared domain: %s", csp)
	}
}

// =============================================================================
// §4.4 Resource Discovery — Visibility
// =============================================================================

// Spec §4.4: Host MUST enforce visibility rules for tools/call from apps.
func TestSpec_Visibility(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	tests := []struct {
		name             string
		toolName         string
		wantError        bool
		allowOtherErrors bool // if true, non-visibility errors are acceptable
	}{
		{"reject_without_app", "model-tool", true, false},
		{"allow_with_app", "app-tool", false, false},
		{"allow_with_both", "both-tool", false, false},
		{"default_allows_app", "unknown-tool", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viewID := "vis-" + tt.name
			vm.Create(viewID)

			resp := postRPC(t, hostServer.URL, viewID, jsonrpcRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params:  map[string]any{"name": tt.toolName, "arguments": map[string]any{}},
			})
			msg := readJSONResponse(t, resp)

			if tt.wantError {
				assert.NotNil(t, msg.Error)
				var errObj map[string]any
				json.Unmarshal(msg.Error, &errObj)
				assert.NotNil(t, errObj["message"])
			} else if msg.Error != nil {
				if !tt.allowOtherErrors {
					t.Fatalf("expected no error, got: %s", string(msg.Error))
				}
				// Non-visibility errors are acceptable; visibility errors are not
				var errObj map[string]any
				json.Unmarshal(msg.Error, &errObj)
				errMsg, _ := errObj["message"].(string)
				if strings.Contains(errMsg, "visibility") {
					t.Error("tool with no declared visibility should default to ['model','app'] and be allowed from apps")
				}
			}
		})
	}
}

// =============================================================================
// §4.7 Sandbox Proxy
// =============================================================================

// Spec §4.7.1: "Host and Sandbox MUST have different origins"
func TestSpec_Sandbox_DifferentOrigins(t *testing.T) {
	_, hs, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	if hs.hostPort == hs.sandboxPort {
		t.Fatal("host and sandbox MUST have different origins (different ports)")
	}
}

// Spec §4.7.2: Sandbox iframe MUST have allow-scripts and allow-same-origin
func TestSpec_Sandbox_IframeHasRequiredSandboxAttributes(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("attr-test")
	vs.HTML = "<html>test</html>"

	resp, err := http.Get(hostServer.URL + "/view/attr-test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// The host page must include sandbox="allow-scripts allow-same-origin ..."
	if !strings.Contains(html, "allow-scripts") {
		t.Error("host page iframe missing allow-scripts in sandbox attribute")
	}
	if !strings.Contains(html, "allow-same-origin") {
		t.Error("host page iframe missing allow-same-origin in sandbox attribute")
	}
}

// Spec §4.7.4: "Once the Sandbox is ready, the Host MUST send the raw HTML
// resource to load in a ui/notifications/sandbox-resource-ready notification."
func TestSpec_Sandbox_SendResourceReadyOnProxyReady(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("ready")
	vs.HTML = "<!DOCTYPE html><html><body>hello</body></html>"

	// Simulate sandbox sending proxy-ready
	resp := postRPC(t, hostServer.URL, "ready", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/sandbox-proxy-ready",
	})
	resp.Body.Close()

	msgs := drainSSE(vs, 50*time.Millisecond)
	if len(msgs) == 0 {
		t.Fatal("MUST send sandbox-resource-ready after sandbox-proxy-ready")
	}
	assert.Equal(t, msgs[0].Method, "ui/notifications/sandbox-resource-ready")
	var params map[string]any
	json.Unmarshal(msgs[0].Params, &params)
	html, _ := params["html"].(string)
	assert.NotEqual(t, html, "")
	assert.Equal(t, html, vs.HTML)
}

// Spec §4.7.6: "The Host MUST NOT send any request or notification to the View
// before it receives an initialized notification."
func TestSpec_Sandbox_NoMessageBeforeInitialized(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("no-early")
	vs.ToolName = "test"
	vs.ToolArgs = json.RawMessage(`{"x":1}`)
	vs.ToolResult = json.RawMessage(`{"content":[]}`)

	// Tool input and result are set, but view is NOT initialized.
	// No tool-input or tool-result should be sent.
	msgs := drainSSE(vs, 50*time.Millisecond)
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-input" ||
			m.Method == "ui/notifications/tool-result" {
			t.Errorf("MUST NOT send %s before initialized", m.Method)
		}
	}
}

// =============================================================================
// §4.12 Container Dimensions — size-changed
// =============================================================================

// Spec §4.12: "When using flexible dimensions, hosts MUST listen for
// ui/notifications/size-changed notifications"
func TestSpec_SizeChanged_AcceptedAsNotification(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("size")

	resp := postRPC(t, hostServer.URL, "size", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/size-changed",
		Params:  map[string]any{"width": 400, "height": 300},
	})
	resp.Body.Close()

	// MUST accept size-changed notifications (204 = notification accepted)
	assert.Equal(t, resp.StatusCode, 204)
}

// =============================================================================
// §4.13 Display Modes
// =============================================================================

// Spec §4.13: "Host MUST return the resulting mode in response to
// ui/request-display-mode"
func TestSpec_DisplayMode_MustReturnResultingMode(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("dm")

	for _, requested := range []string{"inline", "fullscreen", "pip"} {
		resp := postRPC(t, hostServer.URL, "dm", jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      requested, // use mode as id for convenience
			Method:  "ui/request-display-mode",
			Params:  map[string]any{"mode": requested},
		})
		msg := readJSONResponse(t, resp)

		var result map[string]any
		json.Unmarshal(msg.Result, &result)
		mode, ok := result["mode"].(string)
		if !ok || mode == "" {
			t.Errorf("ui/request-display-mode response MUST include 'mode' field for request %q", requested)
		}
	}
}

// Spec §4.13: "If the requested mode is not available, Host SHOULD return
// the current display mode in the response."
func TestSpec_DisplayMode_UnsupportedModeReturnsCurrentMode(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("dm2")

	// Request fullscreen, which we don't support — should return inline
	resp := postRPC(t, hostServer.URL, "dm2", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ui/request-display-mode",
		Params:  map[string]any{"mode": "fullscreen"},
	})
	msg := readJSONResponse(t, resp)

	var result map[string]any
	json.Unmarshal(msg.Result, &result)
	assert.Equal(t, result["mode"], "inline")
}

// =============================================================================
// §4.15 MCP Apps Specific Messages — Notifications Host → View
// =============================================================================

// Spec §4.15: "Host MUST send ui/notifications/tool-input with the complete
// tool arguments after the View's initialize request completes."
func TestSpec_ToolInput_SentAfterInitialized(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("ti")
	vs.ToolName = "my-tool"
	vs.ToolArgs = json.RawMessage(`{"location":"Paris","units":"celsius"}`)

	// Send initialized notification
	resp := postRPC(t, hostServer.URL, "ti", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()

	msgs := drainSSE(vs, 50*time.Millisecond)
	found := false
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-input" {
			found = true
			var params map[string]any
			json.Unmarshal(m.Params, &params)

			// Verify arguments are included
			argsRaw, _ := json.Marshal(params["arguments"])
			if string(argsRaw) == "" || string(argsRaw) == "null" {
				t.Error("tool-input MUST include arguments")
			}
		}
	}
	if !found {
		t.Fatal("MUST send ui/notifications/tool-input after initialized")
	}
}

// Spec §4.15: tool-input "is sent at most once"
func TestSpec_ToolInput_SentAtMostOnce(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("once")
	vs.ToolName = "my-tool"
	vs.ToolArgs = json.RawMessage(`{}`)

	// Send initialized twice
	for range 2 {
		resp := postRPC(t, hostServer.URL, "once", jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/initialized",
		})
		resp.Body.Close()
	}

	msgs := drainSSE(vs, 50*time.Millisecond)
	toolInputCount := 0
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-input" {
			toolInputCount++
		}
	}
	if toolInputCount > 1 {
		t.Errorf("tool-input MUST be sent at most once, but was sent %d times", toolInputCount)
	}
}

// Spec §4.15: "Host MUST send ui/notifications/tool-result when tool execution
// completes (if the View is displayed during tool execution)."
func TestSpec_ToolResult_SentWhenToolCompletes(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("tr")
	vs.ToolName = "my-tool"
	vs.ToolArgs = json.RawMessage(`{}`)

	// Initialize the view
	resp := postRPC(t, hostServer.URL, "tr", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()
	drainSSE(vs, 50*time.Millisecond) // drain tool-input

	// Now deliver tool result
	result := json.RawMessage(`{"content":[{"type":"text","text":"result"}],"structuredContent":{"answer":42}}`)
	vs.SendToolResult(result)

	msgs := drainSSE(vs, 50*time.Millisecond)
	found := false
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-result" {
			found = true
			// Verify the result content is forwarded
			assert.NotNil(t, m.Params)
		}
	}
	if !found {
		t.Fatal("MUST send ui/notifications/tool-result when tool completes")
	}
}

// Spec §4.15: tool-input MUST be sent before tool-result
func TestSpec_ToolInput_SentBeforeToolResult(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("order")
	vs.ToolName = "my-tool"
	vs.ToolArgs = json.RawMessage(`{}`)
	vs.ToolResult = json.RawMessage(`{"content":[]}`)

	// Send initialized — should trigger tool-input, then tool-result
	resp := postRPC(t, hostServer.URL, "order", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()

	msgs := drainSSE(vs, 50*time.Millisecond)
	inputIdx := -1
	resultIdx := -1
	for i, m := range msgs {
		if m.Method == "ui/notifications/tool-input" {
			inputIdx = i
		}
		if m.Method == "ui/notifications/tool-result" {
			resultIdx = i
		}
	}
	if inputIdx == -1 {
		t.Fatal("tool-input not sent")
	}
	if resultIdx == -1 {
		t.Fatal("tool-result not sent")
	}
	if inputIdx >= resultIdx {
		t.Errorf("tool-input (index %d) MUST be sent before tool-result (index %d)", inputIdx, resultIdx)
	}
}

// Spec §4.15: "ui/resource-teardown" — "Host MUST send this before tearing down
// the UI resource"
func TestSpec_Teardown_SentBeforeDestroy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("td")
		vs.mu.Lock()
		vs.Initialized = true
		vs.mu.Unlock()

		// Call teardown in background (it blocks waiting for response)
		done := make(chan struct{})
		go func() {
			vs.SendTeardown()
			close(done)
		}()

		// Read the teardown request from SSE
		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			assert.Equal(t, msg.Method, "ui/resource-teardown")
			assert.NotNil(t, msg.ID)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for teardown request")
		}

		<-done
	})
}

// Spec §4.15: teardown is a request (has id), not a notification
func TestSpec_Teardown_IsRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		vm, _, hostServer, sandboxServer := newTestSetup()
		defer hostServer.Close()
		defer sandboxServer.Close()

		vs := vm.Create("td-req")
		vs.mu.Lock()
		vs.Initialized = true
		vs.mu.Unlock()

		go vs.SendTeardown()

		select {
		case data := <-vs.SSEChan:
			var msg jsonrpcMessage
			json.Unmarshal(data, &msg)
			assert.NotNil(t, msg.ID)
			assert.Equal(t, msg.Method, "ui/resource-teardown")
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	})
}

// =============================================================================
// §4.15 MCP Apps Specific Messages — Requests View → Host
// =============================================================================

// Spec §4.15: View→Host requests MUST return a result.
func TestSpec_ReturnsResult(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	tests := []struct {
		name   string
		method string
		params map[string]any
	}{
		{"open_link", "ui/open-link", map[string]any{"url": "https://example.com"}},
		{"message", "ui/message", map[string]any{
			"role":    "user",
			"content": []map[string]any{{"type": "text", "text": "hello"}},
		}},
		{"update_model_context", "ui/update-model-context", map[string]any{
			"content":           []map[string]any{{"type": "text", "text": "context data"}},
			"structuredContent": map[string]any{"key": "value"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viewID := "ret-" + tt.name
			vm.Create(viewID)

			resp := postRPC(t, hostServer.URL, viewID, jsonrpcRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  tt.method,
				Params:  tt.params,
			})
			msg := readJSONResponse(t, resp)
			assert.NotNil(t, msg.Result)
		})
	}
}

// =============================================================================
// §4.7 — Sandbox Proxy lifecycle ordering
// =============================================================================

// Spec §4.7.6: "The Host MUST NOT send any request or notification to the View
// before it receives an initialized notification."
// Specifically: tool-input must not be sent before initialized.
func TestSpec_Lifecycle_ToolInputNotSentBeforeInitialized(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("lifecycle")
	vs.ToolName = "test"
	vs.ToolArgs = json.RawMessage(`{"key":"val"}`)

	// Do NOT send initialized. Wait briefly and check no tool-input was sent.
	msgs := drainSSE(vs, 50*time.Millisecond)
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-input" {
			t.Error("MUST NOT send tool-input before receiving initialized notification")
		}
	}
}

// Spec: initialized notification should transition the view to active state
func TestSpec_Lifecycle_InitializedSetsState(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("state")
	vs.ToolName = "test"
	vs.ToolArgs = json.RawMessage(`{}`)

	assert.False(t, vs.Initialized)

	resp := postRPC(t, hostServer.URL, "state", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/initialized",
	})
	resp.Body.Close()

	assert.True(t, vs.Initialized)
}

// =============================================================================
// §4.8 — Standard MCP Messages: tools/call, resources/read, ping
// =============================================================================

// Spec §4.8: tools/call proxied to MCP server
func TestSpec_ToolsCall_ProxiedToServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := make(chan string, 1)
		proxy := &mockProxy{
			callToolResult: json.RawMessage(`{"content":[{"type":"text","text":"proxied"}]}`),
		}
		// Wrap to capture calls
		vm, _, hostServer, sandboxServer := newTestSetupWithProxy(&capturingProxy{
			inner:    proxy,
			toolCall: calls,
		}, []ToolInfo{{Name: "my-tool", Visibility: []string{"app"}}})
		defer hostServer.Close()
		defer sandboxServer.Close()

		vm.Create("proxy")

		resp := postRPC(t, hostServer.URL, "proxy", jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params:  map[string]any{"name": "my-tool", "arguments": map[string]any{"q": "test"}},
		})
		msg := readJSONResponse(t, resp)
		if msg.Error != nil {
			t.Fatalf("tools/call should succeed, got error: %s", string(msg.Error))
		}

		select {
		case name := <-calls:
			assert.Equal(t, name, "my-tool")
		case <-time.After(time.Second):
			t.Error("tools/call was not proxied to MCP server")
		}
	})
}

// Spec §4.8: resources/read proxied to MCP server
func TestSpec_ResourcesRead_ProxiedToServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reads := make(chan string, 1)
		proxy := &mockProxy{
			readResult: json.RawMessage(`{"contents":[{"uri":"ui://test","text":"html"}]}`),
		}
		vm, _, hostServer, sandboxServer := newTestSetupWithProxy(&capturingProxy{
			inner:   proxy,
			resRead: reads,
		}, nil)
		defer hostServer.Close()
		defer sandboxServer.Close()

		vm.Create("res")

		resp := postRPC(t, hostServer.URL, "res", jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/read",
			Params:  map[string]any{"uri": "ui://my/resource"},
		})
		msg := readJSONResponse(t, resp)
		if msg.Error != nil {
			t.Fatalf("resources/read should succeed, got error: %s", string(msg.Error))
		}

		select {
		case uri := <-reads:
			assert.Equal(t, uri, "ui://my/resource")
		case <-time.After(time.Second):
			t.Error("resources/read was not proxied to MCP server")
		}
	})
}

// Spec §4.8: "ping" — connection health check, must return result
func TestSpec_Ping_ReturnsEmptyResult(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("p")

	resp := postRPC(t, hostServer.URL, "p", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      42,
		Method:  "ping",
	})
	msg := readJSONResponse(t, resp)
	if msg.Error != nil {
		t.Fatalf("ping should not return error: %s", string(msg.Error))
	}
	assert.NotNil(t, msg.Result)
	// Verify the response ID matches
	idFloat, ok := msg.ID.(float64)
	if !ok || int(idFloat) != 42 {
		t.Errorf("response id should match request id 42, got %v", msg.ID)
	}
}

// =============================================================================
// §4.10 — Host Context in McpUiInitializeResult
// =============================================================================

// Spec §4.10/§4.11: ui/initialize response fields.
func TestSpec_Initialize(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	tests := []struct {
		name  string
		check func(t *testing.T, result map[string]any)
	}{
		{"includes_protocol_version", func(t *testing.T, r map[string]any) {
			if r["protocolVersion"] == nil || r["protocolVersion"] == "" {
				t.Error("ui/initialize response MUST include protocolVersion")
			}
		}},
		{"includes_host_context", func(t *testing.T, r map[string]any) {
			ctx, _ := r["hostContext"].(map[string]any)
			if ctx == nil {
				t.Error("ui/initialize response SHOULD include hostContext")
			}
		}},
		{"includes_host_capabilities", func(t *testing.T, r map[string]any) {
			assert.NotNil(t, r["hostCapabilities"])
		}},
		{"includes_host_info", func(t *testing.T, r map[string]any) {
			hostInfo, ok := r["hostInfo"].(map[string]any)
			if !ok || hostInfo == nil {
				t.Fatal("ui/initialize response MUST include hostInfo")
			}
			if hostInfo["name"] == nil || hostInfo["name"] == "" {
				t.Error("hostInfo MUST include name")
			}
			if hostInfo["version"] == nil || hostInfo["version"] == "" {
				t.Error("hostInfo MUST include version")
			}
		}},
		{"no_legacy_capabilities_key", func(t *testing.T, r map[string]any) {
			assert.Nil(t, r["capabilities"])
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viewID := "init-" + tt.name
			vm.Create(viewID)

			resp := postRPC(t, hostServer.URL, viewID, jsonrpcRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "ui/initialize",
				Params:  map[string]any{"appCapabilities": map[string]any{}},
			})
			msg := readJSONResponse(t, resp)
			var result map[string]any
			json.Unmarshal(msg.Result, &result)

			tt.check(t, result)
		})
	}
}

// =============================================================================
// §4.15 — App-initiated tools/call does NOT echo SSE notifications
// =============================================================================

// When the app calls tools/call (via callServerTool), the host returns
// the result as an RPC response. It should NOT also send tool-input/tool-result
// SSE notifications, since those are for host-initiated tool input only.
func TestSpec_ToolsCall_NoSpuriousSSENotifications(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("sse-notif")

	resp := postRPC(t, hostServer.URL, "sse-notif", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]any{"name": "app-tool", "arguments": map[string]any{"a": 1}},
	})
	readJSONResponse(t, resp)

	msgs := drainSSE(vs, 50*time.Millisecond)
	for _, m := range msgs {
		if m.Method == "ui/notifications/tool-input" {
			t.Error("app-initiated tools/call should not trigger tool-input SSE notification")
		}
		if m.Method == "ui/notifications/tool-result" {
			t.Error("app-initiated tools/call should not trigger tool-result SSE notification")
		}
	}
}

// App-initiated tools/call must return the proxied result directly as the RPC response.
// This is the property that makes SSE notifications unnecessary — the view gets its
// result from the RPC response, not from a separate tool-result notification.
func TestSpec_ToolsCall_ResultInRPCResponse(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("rpc-result")

	resp := postRPC(t, hostServer.URL, "rpc-result", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]any{"name": "app-tool", "arguments": map[string]any{}},
	})
	msg := readJSONResponse(t, resp)

	if msg.Error != nil {
		t.Fatalf("tools/call should succeed, got error: %s", string(msg.Error))
	}

	var result map[string]any
	json.Unmarshal(msg.Result, &result)
	assert.NotNil(t, result["structuredContent"])
}

// =============================================================================
// §4.15 — Notifications View → Host (size-changed, notifications/message)
// =============================================================================

// Spec: notifications from view (no id) should return 204
func TestSpec_ViewNotification_Returns204(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("notif")

	// notifications/message (log)
	resp := postRPC(t, hostServer.URL, "notif", jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "notifications/message",
		Params:  map[string]any{"level": "info", "data": "test log"},
	})
	resp.Body.Close()
	assert.Equal(t, resp.StatusCode, 204)
}

// =============================================================================
// Edge cases: error handling
// =============================================================================

// Spec: tools/call with invalid params returns JSON-RPC error
func TestSpec_ToolsCall_InvalidParams(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("err")

	// Send tools/call with no params at all (missing name)
	resp := postRPC(t, hostServer.URL, "err", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	})
	msg := readJSONResponse(t, resp)
	assert.NotNil(t, msg.Error)
}

// Spec: tools/call proxy error returns JSON-RPC error to view
func TestSpec_ToolsCall_ProxyError(t *testing.T) {
	proxy := &mockProxy{
		callToolErr: errors.New("server unavailable"),
	}
	vm, _, hostServer, sandboxServer := newTestSetupWithProxy(proxy, []ToolInfo{{Name: "app-tool", Visibility: []string{"app"}}})
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("proxy-err")

	resp := postRPC(t, hostServer.URL, "proxy-err", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  map[string]any{"name": "app-tool", "arguments": map[string]any{}},
	})
	msg := readJSONResponse(t, resp)
	assert.NotNil(t, msg.Error)
}

// Spec: resources/read proxy error returns JSON-RPC error to view
func TestSpec_ResourcesRead_ProxyError(t *testing.T) {
	proxy := &mockProxy{
		readErr: errors.New("resource not found"),
	}
	vm, _, hostServer, sandboxServer := newTestSetupWithProxy(proxy, nil)
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("res-err")

	resp := postRPC(t, hostServer.URL, "res-err", jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "resources/read",
		Params:  map[string]any{"uri": "ui://missing"},
	})
	msg := readJSONResponse(t, resp)
	assert.NotNil(t, msg.Error)
}

// JSON-RPC: response id must match request id
func TestSpec_JSONRPC_ResponseIdMatchesRequestId(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vm.Create("id")

	for _, id := range []any{1, "abc", 999} {
		resp := postRPC(t, hostServer.URL, "id", jsonrpcRequest{
			JSONRPC: "2.0",
			ID:      id,
			Method:  "ping",
		})
		msg := readJSONResponse(t, resp)
		// JSON numbers get parsed as float64
		expected := fmt.Sprintf("%v", id)
		got := fmt.Sprintf("%v", msg.ID)
		assert.Equal(t, got, expected)
	}
}

// =============================================================================
// §4.7 — CSP headers served on sandbox page
// =============================================================================

// Spec §4.7.5: "The Sandbox MUST load the raw HTML of the View with CSP settings"
// Verify CSP is served as HTTP header on the sandbox page
func TestSpec_Sandbox_CSPServedAsHTTPHeader(t *testing.T) {
	vm, _, hostServer, sandboxServer := newTestSetup()
	defer hostServer.Close()
	defer sandboxServer.Close()

	vs := vm.Create("csp-header")
	vs.csp = &ResourceCSP{
		ConnectDomains: []string{"https://api.example.com"},
	}

	resp, err := http.Get(sandboxServer.URL + "/sandbox/csp-header")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("sandbox page MUST serve Content-Security-Policy HTTP header")
	}
	if !strings.Contains(csp, "https://api.example.com") {
		t.Errorf("CSP header should include declared connect domain: %s", csp)
	}
}
