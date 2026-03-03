// host.go implements the MCP protocol handlers and sandbox server.
//
// HostServer owns the view lifecycle, JSON-RPC dispatch, and sandbox origin.
// User-facing routes (index, create, static, hot-reload) live in app.go.
//
// Message flow: Browser ↔ Host SSE/RPC ↔ JSON-RPC dispatch ↔ MCP server
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yurivish/mcp/internal/host/templates"
)

// ── Core abstractions ──

// ToolInfo is the template type reexported for use in the main package.
type ToolInfo = templates.ToolInfo

// MCPProxy abstracts the MCP client session for host.go.
type MCPProxy interface {
	CallTool(name string, args json.RawMessage) (json.RawMessage, error)
	ReadResource(uri string) (json.RawMessage, error)
}

// ── Host server ──

// HostServer holds the HTTP handlers for the host and sandbox servers.
type HostServer struct {
	vm          *ViewManager
	hostPort    string
	sandboxPort string
	mcpProxy    MCPProxy // Interface for proxying tools/call and resources/read to the MCP server
	tools       func() []ToolInfo
	HostName    string
	HostVersion string
}

func NewHostServer(vm *ViewManager, hostPort, sandboxPort string, proxy MCPProxy, tools func() []ToolInfo) *HostServer {
	return &HostServer{
		vm:          vm,
		hostPort:    hostPort,
		sandboxPort: sandboxPort,
		mcpProxy:    proxy,
		tools:       tools,
		HostName:    "mcphost",
		HostVersion: "0.1.0",
	}
}

// origin returns an origin URL using the request's hostname and the given port.
func (hs *HostServer) origin(r *http.Request, port string) string {
	hostname := r.Host
	if i := strings.LastIndex(hostname, ":"); i != -1 {
		hostname = hostname[:i]
	}
	return "http://" + hostname + ":" + port
}

// SandboxMux returns the HTTP mux for the sandbox server (:8081).
func (hs *HostServer) SandboxMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sandbox/{id}", hs.handleSandboxPage)
	return mux
}

// ── CreateToolCall — the main orchestration ──

// CreateToolCallResult represents the outcome of CreateToolCall.
type CreateToolCallResult struct {
	ViewURL string          // Set if the tool has UI (path like "/view/v0")
	Result  json.RawMessage // Set if the tool has no UI (direct tool result)
}

// CreateToolCall orchestrates a tool call: finds the tool, fetches UI resource
// if needed, creates a view, and calls the tool asynchronously (for UI tools)
// or synchronously (for non-UI tools).
func (hs *HostServer) CreateToolCall(toolName string, args json.RawMessage) (*CreateToolCallResult, error) {
	tools := hs.tools()
	var tool *ToolInfo
	for i := range tools {
		if tools[i].Name == toolName {
			tool = &tools[i]
			break
		}
	}
	if tool == nil {
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}

	if tool.ResourceURI != "" {
		viewID := hs.vm.NextID()

		result, err := hs.mcpProxy.ReadResource(tool.ResourceURI)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch UI resource: %w", err)
		}

		html, csp := extractHTMLAndCSP(result)

		vs := hs.vm.Create(viewID)
		vs.HTML = html
		vs.csp = csp
		vs.ToolName = toolName
		vs.ToolArgs = args

		go func() {
			toolResult, err := hs.mcpProxy.CallTool(toolName, args)
			if err != nil {
				log.Printf("Tool call error: %v", err)
				errResult, _ := json.Marshal(map[string]any{
					"content": []map[string]any{{"type": "text", "text": err.Error()}},
					"isError": true,
				})
				vs.SendToolResult(errResult)
				return
			}
			vs.SendToolResult(toolResult)
			log.Printf("Tool %s result delivered to view %s", toolName, viewID)
		}()

		return &CreateToolCallResult{ViewURL: "/view/" + viewID}, nil
	}

	// No UI — call tool directly
	result, err := hs.mcpProxy.CallTool(toolName, args)
	if err != nil {
		return nil, err
	}
	return &CreateToolCallResult{Result: result}, nil
}

// ── Resource extraction helpers ──

// extractHTMLAndCSP extracts text and CSP from a ReadResource JSON result.
func extractHTMLAndCSP(raw json.RawMessage) (string, *ResourceCSP) {
	var result struct {
		Contents []struct {
			Text string `json:"text"`
			Meta struct {
				UI struct {
					CSP *ResourceCSP `json:"csp"`
				} `json:"ui"`
			} `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Contents) == 0 {
		return "", nil
	}
	return result.Contents[0].Text, result.Contents[0].Meta.UI.CSP
}

// ── View lifecycle ──

// ViewState tracks the state of a single UI view.
type ViewState struct {
	ID  string
	mu  sync.Mutex
	csp *ResourceCSP
	ctx context.Context

	// The fetched HTML content for the view
	HTML string

	// Tool invocation info
	ToolName   string
	ToolArgs   json.RawMessage
	ToolResult json.RawMessage // Raw JSON of the CallToolResult

	// Lifecycle
	Initialized     bool
	ToolInputSent   bool
	SSEChan         chan []byte // Channel for SSE messages to browser
	PendingRequests sync.Map    // id → chan json.RawMessage (for teardown responses)
}

// ViewManager holds all active views.
type ViewManager struct {
	mu      sync.Mutex
	views   map[string]*ViewState
	counter int
	ctx     context.Context
}

func NewViewManager(ctx context.Context) *ViewManager {
	return &ViewManager{views: make(map[string]*ViewState), ctx: ctx}
}

// NextID returns a unique view ID.
func (vm *ViewManager) NextID() string {
	vm.mu.Lock()
	id := fmt.Sprintf("v%d", vm.counter)
	vm.counter++
	vm.mu.Unlock()
	return id
}

func (vm *ViewManager) Create(id string) *ViewState {
	vs := &ViewState{
		ID:      id,
		SSEChan: make(chan []byte, 64),
		ctx:     vm.ctx,
	}
	vm.mu.Lock()
	vm.views[id] = vs
	vm.mu.Unlock()
	return vs
}

func (vm *ViewManager) Get(id string) *ViewState {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.views[id]
}

// TeardownAll sends teardown to all active views.
func (vm *ViewManager) TeardownAll() {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	for _, vs := range vm.views {
		vs.SendTeardown()
	}
}

// sendSSE sends a JSON-RPC message to the view's SSE channel.
func (vs *ViewState) sendSSE(msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case vs.SSEChan <- data:
	default:
		log.Printf("view %s: SSE channel full, dropping message", vs.ID)
	}
	return nil
}

// ── HTTP handlers: view pages and event stream ──

func (hs *HostServer) handleViewPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vs := hs.vm.Get(id)
	if vs == nil {
		http.NotFound(w, r)
		return
	}
	sbOrigin := hs.origin(r, hs.sandboxPort)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.View(id, sbOrigin, sbOrigin+"/sandbox/"+id).Render(r.Context(), w)
}

func (hs *HostServer) handleViewSSE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vs := hs.vm.Get(id)
	if vs == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial keepalive
	fmt.Fprintf(w, ": keepalive\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-vs.ctx.Done():
			// Drain remaining messages (e.g. teardown) before closing
			for {
				select {
				case data := <-vs.SSEChan:
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				default:
					return
				}
			}
		case <-r.Context().Done():
			return
		case data := <-vs.SSEChan:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ── HTTP handlers: JSON-RPC dispatch ──

// handleViewRPC is the central JSON-RPC dispatcher for view↔host communication.
// It receives messages from the browser (via the sandbox proxy), routes responses
// to pending requests, and dispatches method calls to the appropriate handler.
func (hs *HostServer) handleViewRPC(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vs := hs.vm.Get(id)
	if vs == nil {
		http.NotFound(w, r)
		return
	}

	var msg jsonrpcMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	log.Printf("view %s: RPC >>> method=%q id=%v", id, msg.Method, msg.ID)
	defer log.Printf("view %s: RPC <<< method=%q id=%v", id, msg.Method, msg.ID)

	// If this is a response (has result or error, with id but no method), deliver to pending request
	if msg.Method == "" && msg.ID != nil {
		idStr := fmt.Sprintf("%v", msg.ID)
		if ch, ok := vs.PendingRequests.LoadAndDelete(idStr); ok {
			raw, _ := json.Marshal(msg)
			ch.(chan json.RawMessage) <- raw
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Dispatch based on method
	switch msg.Method {
	case "ui/notifications/sandbox-proxy-ready":
		hs.handleSandboxReady(vs)
		w.WriteHeader(http.StatusNoContent)

	case "ui/initialize":
		hs.handleInitialize(vs, msg, w)

	case "ui/notifications/initialized":
		hs.handleInitialized(vs)
		w.WriteHeader(http.StatusNoContent)

	case "ui/notifications/size-changed":
		log.Printf("view %s: size-changed: %s", id, string(msg.Params))
		w.WriteHeader(http.StatusNoContent)

	case "tools/call":
		hs.handleToolsCall(vs, msg, w)

	case "resources/read":
		hs.handleResourcesRead(vs, msg, w)

	case "ui/open-link", "ui/message", "ui/update-model-context":
		log.Printf("view %s: %s: %s", id, msg.Method, string(msg.Params))
		writeJSONRPC(w, msg.ID, map[string]any{})

	case "ui/request-display-mode":
		writeJSONRPC(w, msg.ID, map[string]any{"mode": "inline"})

	case "notifications/message":
		log.Printf("view %s: notification: %s", id, string(msg.Params))
		w.WriteHeader(http.StatusNoContent)

	case "ping":
		writeJSONRPC(w, msg.ID, map[string]any{})

	default:
		log.Printf("view %s: unknown method %q", id, msg.Method)
		writeJSONRPCError(w, msg.ID, -32601, "method not found")
	}
}

// ── RPC method handlers (lifecycle order) ──

func (hs *HostServer) handleSandboxReady(vs *ViewState) {
	log.Printf("view %s: sandbox ready, sending resource HTML", vs.ID)
	vs.sendSSE(jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "ui/notifications/sandbox-resource-ready",
		Params: map[string]any{
			"html": vs.HTML,
			"sandbox": map[string]any{
				"permissions": map[string]any{},
			},
		},
	})
}

func (hs *HostServer) handleInitialize(vs *ViewState, msg jsonrpcMessage, w http.ResponseWriter) {
	log.Printf("view %s: ui/initialize", vs.ID)
	writeJSONRPC(w, msg.ID, map[string]any{
		"protocolVersion": "2025-06-18",
		"hostInfo": map[string]any{
			"name":    hs.HostName,
			"version": hs.HostVersion,
		},
		"hostCapabilities": map[string]any{
			"notifications": map[string]any{
				"toolInput":  true,
				"toolResult": true,
			},
		},
		"hostContext": map[string]any{
			"displayMode": "inline",
		},
	})
}

// handleInitialized processes the initialized notification from the view.
// This is the gate that enables host→view communication: tool-input and
// tool-result notifications are buffered until initialized is received,
// then delivered in order (tool-input first, then tool-result if available).
func (hs *HostServer) handleInitialized(vs *ViewState) {
	vs.mu.Lock()
	vs.Initialized = true
	needToolInput := !vs.ToolInputSent && vs.ToolArgs != nil
	hasToolResult := vs.ToolResult != nil
	if needToolInput {
		vs.ToolInputSent = true
	}
	vs.mu.Unlock()

	log.Printf("view %s: initialized", vs.ID)

	// Send tool-input notification now that view is initialized
	if needToolInput {
		vs.sendSSE(jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/tool-input",
			Params: map[string]any{
				"toolName":  vs.ToolName,
				"arguments": json.RawMessage(vs.ToolArgs),
			},
		})
	}

	// If tool result already arrived, send it too
	if hasToolResult {
		vs.sendSSE(jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/tool-result",
			Params:  json.RawMessage(vs.ToolResult),
		})
	}
}

func (hs *HostServer) handleToolsCall(vs *ViewState, msg jsonrpcMessage, w http.ResponseWriter) {
	// Parse the tools/call params
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		writeJSONRPCError(w, msg.ID, -32602, "invalid params")
		return
	}

	// Check visibility — tool must have "app" visibility.
	// Per spec, tools with no declared visibility default to ["model", "app"],
	// so we only reject when visibility is explicitly declared without "app".
	tools := hs.tools()
	var vis []string
	for _, t := range tools {
		if t.Name == params.Name {
			vis = t.Visibility
			break
		}
	}
	if len(vis) > 0 {
		hasApp := slices.Contains(vis, "app")
		if !hasApp {
			writeJSONRPCError(w, msg.ID, -32600, "tool does not have app visibility")
			return
		}
	}

	// Proxy to MCP server
	result, err := hs.mcpProxy.CallTool(params.Name, params.Arguments)
	if err != nil {
		writeJSONRPCError(w, msg.ID, -32603, err.Error())
		return
	}

	// Return the CallToolResult as the RPC response
	writeJSONRPC(w, msg.ID, result)
}

func (hs *HostServer) handleResourcesRead(vs *ViewState, msg jsonrpcMessage, w http.ResponseWriter) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		writeJSONRPCError(w, msg.ID, -32602, "invalid params")
		return
	}

	result, err := hs.mcpProxy.ReadResource(params.URI)
	if err != nil {
		writeJSONRPCError(w, msg.ID, -32603, err.Error())
		return
	}

	writeJSONRPC(w, msg.ID, result)
}

// ── Sandbox handlers ──

func (hs *HostServer) handleSandboxPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vs := hs.vm.Get(id)
	if vs == nil {
		http.NotFound(w, r)
		return
	}

	// Set CSP headers based on the view's resource metadata
	cspHeader := buildCSP(vs.csp)
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates.Sandbox().Render(r.Context(), w)
}

// ── View notifications (host → view) ──

// SendToolResult sends the tool result notification to the view via SSE.
// Called from view.go after the tool call completes.
func (vs *ViewState) SendToolResult(result json.RawMessage) {
	vs.mu.Lock()
	vs.ToolResult = result
	initialized := vs.Initialized
	vs.mu.Unlock()

	if initialized {
		vs.sendSSE(jsonrpcNotification{
			JSONRPC: "2.0",
			Method:  "ui/notifications/tool-result",
			Params:  json.RawMessage(result),
		})
	}
	// If not yet initialized, handleInitialized will send it when the view is ready
}

// SendTeardown sends ui/resource-teardown to the view (best-effort).
func (vs *ViewState) SendTeardown() {
	vs.sendSSE(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      "teardown-" + vs.ID,
		Method:  "ui/resource-teardown",
	})
	log.Printf("view %s: teardown sent", vs.ID)
}

// ── JSON-RPC types and helpers ──

// JSON-RPC message types for the host↔view protocol.
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

type jsonrpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func writeJSONRPC(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
