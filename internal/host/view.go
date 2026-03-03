// mcphost is a minimal MCP UI host that connects to an MCP server subprocess
// and serves its UI tools in a browser. It uses a dual-port architecture:
// the host server (:8080) handles the tool index, view pages, and JSON-RPC
// dispatch, while the sandbox server (:8081) serves tool UI HTML in an
// isolated origin with per-resource CSP headers.
//
// The codebase is split across four files:
//   - view.go: entry point, MCP session management, and tool discovery
//   - app.go:  user-facing HTTP layer (index page, form submission, live reload)
//   - host.go: HTTP servers, view lifecycle, and JSON-RPC message handling
//   - csp.go:  Content-Security-Policy header construction
package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yurivish/toolkit/pubsub"
)

// ── Configuration ──

const (
	hostPort    = "8080"
	sandboxPort = "8081"
)

// ── Entry point ──

func Run(ctx context.Context, args []string) error {
	// Derive a cancellable context so background goroutines exit when Run returns.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if len(args) == 0 {
		return fmt.Errorf("usage: mcphost <server-command> [args...]\nExample: mcphost go run ./cmd/testserver")
	}

	// Create PubSub for reload notifications
	ps := pubsub.NewPubSub()

	// Create MCP client with ui extension capability
	caps := &mcp.ClientCapabilities{}
	caps.AddExtension("io.modelcontextprotocol/ui", nil)

	client := mcp.NewClient(
		&mcp.Implementation{Name: "mcphost", Version: "0.1.0"},
		&mcp.ClientOptions{Capabilities: caps},
	)

	// Set up the channel-based session proxy
	ops := make(chan sessionOp)
	proxy := &sessionProxy{ops: ops, ctx: ctx}

	// Atomic pointer for dynamic tools list, updated on each (re)connect
	var toolsPtr atomic.Pointer[[]ToolInfo]
	ready := make(chan struct{})
	var once sync.Once

	// Set up the view manager with its own context so SSE handlers stay alive
	// until teardown messages are delivered (not killed by the signal context).
	vmCtx, vmCancel := context.WithCancel(context.Background())
	defer vmCancel()
	vm := NewViewManager(vmCtx)
	hs := NewHostServer(vm, hostPort, sandboxPort, proxy, func() []ToolInfo {
		if p := toolsPtr.Load(); p != nil {
			return *p
		}
		return nil
	})
	app := NewApp(hs, ps)

	onRestart := func(tools []ToolInfo) {
		toolsPtr.Store(&tools)
		once.Do(func() { close(ready) })
	}

	// Start the session goroutine (sole owner of the MCP session)
	go runSession(ctx, client, args, ops, onRestart)

	// Wait for initial connection
	<-ready

	tools := toolsPtr.Load()
	if tools == nil || len(*tools) == 0 {
		return errors.New("no tools available from server")
	}

	// Start HTTP servers
	hostSrv := &http.Server{Addr: "0.0.0.0:" + hostPort, Handler: app.Mux()}
	sandboxSrv := &http.Server{Addr: "0.0.0.0:" + sandboxPort, Handler: hs.SandboxMux()}

	go func() {
		log.Printf("Host server listening on 0.0.0.0:%s", hostPort)
		if err := hostSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Host server error: %v", err)
		}
	}()
	go func() {
		log.Printf("Sandbox server listening on 0.0.0.0:%s", sandboxPort)
		if err := sandboxSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Sandbox server error: %v", err)
		}
	}()

	// Print available tools
	fmt.Println("\nAvailable tools:")
	for _, ti := range *tools {
		marker := ""
		if ti.ResourceURI != "" {
			marker = " [has UI]"
		}
		if len(ti.Visibility) > 0 {
			marker += fmt.Sprintf(" (visibility: %v)", ti.Visibility)
		}
		fmt.Printf("  - %s: %s%s\n", ti.Name, ti.Description, marker)
	}
	fmt.Println()

	// Start binary watcher for live reload
	if watchPath := resolveWatchPath(args); watchPath != "" {
		log.Printf("Watching %s for changes (live reload enabled)", watchPath)
		go watchBinary(ctx, watchPath, ops, app)
	} else {
		log.Println("Live reload disabled (command is not a binary on disk)")
	}

	// Block until interrupted (Ctrl+C)
	<-ctx.Done()
	log.Println("Shutting down...")

	// Send teardown to all active views, then close SSE connections
	vm.TeardownAll()
	vmCancel()

	// Gracefully shut down HTTP servers
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	hostSrv.Shutdown(shutdownCtx)
	sandboxSrv.Shutdown(shutdownCtx)

	return nil
}

// ── MCP session management ──

// Session operation types for the channel-based proxy.
type opKind int

const (
	opCallTool opKind = iota
	opReadResource
	opRestart
)

type sessionOp struct {
	kind            opKind
	callToolName    string
	callToolArgs    json.RawMessage
	readResourceURI string
	reply           chan sessionResult
}

type sessionResult struct {
	data json.RawMessage
	err  error
}

// sessionProxy implements MCPProxy by sending operations to the session goroutine.
// It uses the context to bail out immediately if the app is shutting down,
// preventing hangs when runSession has already exited.
type sessionProxy struct {
	ops chan sessionOp
	ctx context.Context
}

func (p *sessionProxy) CallTool(name string, args json.RawMessage) (json.RawMessage, error) {
	reply := make(chan sessionResult, 1)
	select {
	case p.ops <- sessionOp{kind: opCallTool, callToolName: name, callToolArgs: args, reply: reply}:
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
	select {
	case r := <-reply:
		return r.data, r.err
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

func (p *sessionProxy) ReadResource(uri string) (json.RawMessage, error) {
	reply := make(chan sessionResult, 1)
	select {
	case p.ops <- sessionOp{kind: opReadResource, readResourceURI: uri, reply: reply}:
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
	select {
	case r := <-reply:
		return r.data, r.err
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

// runSession is the session goroutine — sole owner of the MCP session.
// CallTool and ReadResource are dispatched to goroutines so the event
// loop stays responsive; this prevents deadlocks when a UI tool's
// handler calls back into the host (e.g. tools/call from within a view).
// Restart remains synchronous to ensure the old session is fully closed
// before the new one is created.
func runSession(ctx context.Context, client *mcp.Client, cmdArgs []string,
	ops chan sessionOp, onRestart func([]ToolInfo)) {
	session, tools := connectSession(ctx, client, cmdArgs)
	onRestart(tools)

	for {
		select {
		case op := <-ops:
			switch op.kind {
			case opCallTool:
				if session == nil {
					op.reply <- sessionResult{err: errors.New("MCP server not connected")}
					continue
				}
				s := session
				go func() {
					result, err := s.CallTool(ctx, &mcp.CallToolParams{
						Name:      op.callToolName,
						Arguments: op.callToolArgs,
					})
					if err != nil {
						op.reply <- sessionResult{err: err}
					} else {
						data, mErr := json.Marshal(result)
						op.reply <- sessionResult{data: data, err: mErr}
					}
				}()
			case opReadResource:
				if session == nil {
					op.reply <- sessionResult{err: errors.New("MCP server not connected")}
					continue
				}
				s := session
				go func() {
					result, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: op.readResourceURI})
					if err != nil {
						op.reply <- sessionResult{err: err}
					} else {
						data, mErr := json.Marshal(result)
						op.reply <- sessionResult{data: data, err: mErr}
					}
				}()
			case opRestart:
				if session != nil {
					session.Close()
				}
				session, tools = connectSession(ctx, client, cmdArgs)
				onRestart(tools)
				op.reply <- sessionResult{}
			}
		case <-ctx.Done():
			if session != nil {
				session.Close()
			}
			return
		}
	}
}

// connectSession creates a new MCP server subprocess and connects to it.
func connectSession(ctx context.Context, client *mcp.Client, cmdArgs []string) (*mcp.ClientSession, []ToolInfo) {
	serverCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	serverCmd.Stderr = os.Stderr
	transport := &mcp.CommandTransport{Command: serverCmd}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Printf("Failed to connect to MCP server: %v", err)
		return nil, nil
	}

	log.Println("Connected to MCP server")

	tools, err := collectTools(ctx, session)
	if err != nil {
		log.Printf("Failed to list tools: %v", err)
		session.Close()
		return nil, nil
	}

	return session, buildToolInfos(tools)
}

// ── Tool discovery ──

// collectTools collects all tools from the session into a slice.
func collectTools(ctx context.Context, session *mcp.ClientSession) ([]*mcp.Tool, error) {
	var tools []*mcp.Tool
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

// buildToolInfos converts MCP tools to ToolInfo structs for display.
func buildToolInfos(tools []*mcp.Tool) []ToolInfo {
	var infos []ToolInfo
	for _, t := range tools {
		ti := ToolInfo{
			Name:        t.Name,
			Description: t.Description,
			ResourceURI: getToolResourceURI(t),
			Visibility:  getToolVisibility(t),
		}
		ti.SchemaJSON, ti.ExampleJSON = schemaAndExample(t.InputSchema)
		infos = append(infos, ti)
	}
	return infos
}

// getToolUI returns t.Meta["ui"] as a map, or nil if absent/wrong type.
func getToolUI(t *mcp.Tool) map[string]any {
	ui, ok := t.Meta["ui"]
	if !ok {
		return nil
	}
	m, _ := ui.(map[string]any)
	return m
}

// getToolResourceURI extracts _meta.ui.resourceUri from a tool's metadata.
func getToolResourceURI(t *mcp.Tool) string {
	ui := getToolUI(t)
	if ui == nil {
		return ""
	}
	uri, _ := ui["resourceUri"].(string)
	return uri
}

// getToolVisibility extracts _meta.ui.visibility from a tool's metadata.
func getToolVisibility(t *mcp.Tool) []string {
	ui := getToolUI(t)
	if ui == nil {
		return nil
	}
	visList, ok := ui["visibility"].([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, v := range visList {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// schemaAndExample returns a pretty-printed JSON schema string and an example
// JSON object with placeholder values generated from the schema's properties.
func schemaAndExample(inputSchema any) (schemaJSON, exampleJSON string) {
	m, ok := inputSchema.(map[string]any)
	if !ok || m == nil {
		return "", "{}"
	}

	// Pretty-print the schema (omit the outer $schema/additionalProperties noise)
	props, hasProps := m["properties"].(map[string]any)
	if hasProps {
		b, _ := json.MarshalIndent(props, "", "  ")
		schemaJSON = string(b)
	}

	// Generate example from properties
	example := make(map[string]any)
	if hasProps {
		for name, propRaw := range props {
			prop, ok := propRaw.(map[string]any)
			if !ok {
				example[name] = ""
				continue
			}
			typ, _ := prop["type"].(string)
			desc, _ := prop["description"].(string)
			switch typ {
			case "string":
				if desc != "" {
					example[name] = desc
				} else {
					example[name] = ""
				}
			case "number", "integer":
				example[name] = 0
			case "boolean":
				example[name] = false
			case "array":
				example[name] = []any{}
			case "object":
				example[name] = map[string]any{}
			default:
				example[name] = ""
			}
		}
	}

	b, _ := json.MarshalIndent(example, "", "  ")
	exampleJSON = string(b)
	return schemaJSON, exampleJSON
}

// ── Live reload ──

// resolveWatchPath returns the path to watch if the command is a binary on disk,
// or empty string if it's not watchable (e.g., "go run" or other non-file commands).
func resolveWatchPath(cmdArgs []string) string {
	path := cmdArgs[0]
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	return path
}

// watchBinary polls the binary file for changes and triggers a session restart.
// After the restart completes, it refreshes all stored tool results against
// the new session and then signals browsers to reload.
func watchBinary(ctx context.Context, path string, ops chan sessionOp, app *App) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	lastMod := info.ModTime()

	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if !info.ModTime().Equal(lastMod) {
				lastMod = info.ModTime()
				log.Printf("Binary %s changed, restarting MCP server...", path)
				reply := make(chan sessionResult, 1)
				select {
				case ops <- sessionOp{kind: opRestart, reply: reply}:
					<-reply
					log.Println("MCP server restarted")
					app.refreshResults()
					pubsub.Pub(app.ps, "reload", struct{}{})
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
