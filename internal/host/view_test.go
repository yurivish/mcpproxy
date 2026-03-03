// view_test.go tests tool metadata extraction from mcp.Tool and live reload.
package host

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yurivish/toolkit/assert"
	"github.com/yurivish/toolkit/pubsub"
)

// =============================================================================
// Tool metadata extraction — getToolUI, getToolResourceURI, getToolVisibility
// =============================================================================

// getToolUI returns the ui map when present, nil for absent/wrong-type/nil Meta.
func TestGetToolUI(t *testing.T) {
	tests := []struct {
		name string
		tool *mcp.Tool
		want map[string]any // nil means expect nil
	}{
		{"present", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"key": "value"}}}, map[string]any{"key": "value"}},
		{"absent", &mcp.Tool{Meta: mcp.Meta{"other": 1}}, nil},
		{"wrong_type", &mcp.Tool{Meta: mcp.Meta{"ui": "not a map"}}, nil},
		{"nil_meta", &mcp.Tool{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getToolUI(tt.tool)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				if got == nil {
					t.Fatal("expected non-nil ui map")
				}
				for k, v := range tt.want {
					assert.Equal(t, got[k], v)
				}
			}
		})
	}
}

// getToolResourceURI returns the URI when present, empty string otherwise.
func TestGetToolResourceURI(t *testing.T) {
	tests := []struct {
		name string
		tool *mcp.Tool
		want string
	}{
		{"present", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"resourceUri": "ui://test"}}}, "ui://test"},
		{"no_ui", &mcp.Tool{}, ""},
		{"ui_without_resourceUri", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"other": "value"}}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getToolResourceURI(tt.tool)
			assert.Equal(t, got, tt.want)
		})
	}
}

// getToolVisibility returns string slice for valid array, nil for absent/wrong type,
// and skips non-string elements in the array.
func TestGetToolVisibility(t *testing.T) {
	tests := []struct {
		name string
		tool *mcp.Tool
		want []string // nil means expect nil
	}{
		{"valid_array", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"visibility": []any{"model", "app"}}}}, []string{"model", "app"}},
		{"no_ui", &mcp.Tool{}, nil},
		{"not_array", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"visibility": "model"}}}, nil},
		{"mixed_types_skips_non_strings", &mcp.Tool{Meta: mcp.Meta{"ui": map[string]any{"visibility": []any{"app", 42, "model"}}}}, []string{"app", "model"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getToolVisibility(tt.tool)
			assert.Equal(t, got, tt.want)
		})
	}
}

// =============================================================================
// Schema and example generation
// =============================================================================

// nil, non-map, or map-without-properties inputSchema returns empty schema and "{}" example.
func TestSchemaAndExample(t *testing.T) {
	tests := []struct {
		name        string
		input       any
		wantSchema  string
		wantExample string
	}{
		{"nil", nil, "", "{}"},
		{"non_map", "not a map", "", "{}"},
		{"no_properties", map[string]any{"type": "object"}, "", "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema, example := schemaAndExample(tt.input)
			assert.Equal(t, schema, tt.wantSchema)
			assert.Equal(t, example, tt.wantExample)
		})
	}
}

// Each property type produces the correct placeholder value in the example.
func TestSchemaAndExample_AllTypes(t *testing.T) {
	input := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":   map[string]any{"type": "string", "description": "User name"},
			"label":  map[string]any{"type": "string"},
			"count":  map[string]any{"type": "integer"},
			"score":  map[string]any{"type": "number"},
			"active": map[string]any{"type": "boolean"},
			"tags":   map[string]any{"type": "array"},
			"config": map[string]any{"type": "object"},
			"other":  map[string]any{"type": "custom"},
		},
	}
	schema, example := schemaAndExample(input)

	assert.NotEqual(t, schema, "")

	var ex map[string]any
	if err := json.Unmarshal([]byte(example), &ex); err != nil {
		t.Fatalf("failed to parse example JSON: %v", err)
	}

	// String with description uses description as placeholder
	assert.Equal(t, ex["name"], "User name")
	// String without description uses empty string
	assert.Equal(t, ex["label"], "")
	// integer → 0 (JSON numbers are float64)
	assert.Equal[any](t, ex["count"], float64(0))
	// number → 0
	assert.Equal[any](t, ex["score"], float64(0))
	// boolean → false
	assert.Equal[any](t, ex["active"], false)
	// array → []
	if arr, ok := ex["tags"].([]any); !ok || len(arr) != 0 {
		t.Errorf("array: expected [], got %v", ex["tags"])
	}
	// object → {}
	if obj, ok := ex["config"].(map[string]any); !ok || len(obj) != 0 {
		t.Errorf("object: expected {}, got %v", ex["config"])
	}
	// unknown type → ""
	assert.Equal(t, ex["other"], "")
}

// =============================================================================
// buildToolInfos
// =============================================================================

// Converts mcp.Tool slice to ToolInfo slice, populating all fields.
// nil input returns nil; populated tools produce correct metadata.
func TestBuildToolInfos(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		infos := buildToolInfos(nil)
		assert.Nil(t, infos)
	})

	t.Run("populated", func(t *testing.T) {
		tools := []*mcp.Tool{{
			Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": "ui://tool", "visibility": []any{"app"}}},
			Name:        "my-tool",
			Description: "Does stuff",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
				},
			},
		}}
		infos := buildToolInfos(tools)
		if len(infos) != 1 {
			t.Fatalf("expected 1 ToolInfo, got %d", len(infos))
		}
		ti := infos[0]
		assert.Equal(t, ti.Name, "my-tool")
		assert.Equal(t, ti.Description, "Does stuff")
		assert.Equal(t, ti.ResourceURI, "ui://tool")
		assert.Equal(t, ti.Visibility, []string{"app"})
		assert.NotEqual(t, ti.SchemaJSON, "")
		assert.NotEqual(t, ti.ExampleJSON, "")
	})
}

// =============================================================================
// Live reload — resolveWatchPath
// =============================================================================

// Existing file on disk returns its path.
func TestResolveWatchPath_File(t *testing.T) {
	f, err := os.CreateTemp("", "watchtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	path := resolveWatchPath([]string{f.Name()})
	assert.Equal(t, path, f.Name())
}

// Directory returns empty string (not watchable).
func TestResolveWatchPath_Directory(t *testing.T) {
	dir, err := os.MkdirTemp("", "watchtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dir)

	path := resolveWatchPath([]string{dir})
	assert.Equal(t, path, "")
}

// Non-existent path returns empty string.
func TestResolveWatchPath_NonExistent(t *testing.T) {
	path := resolveWatchPath([]string{"/nonexistent/path/binary"})
	assert.Equal(t, path, "")
}

// =============================================================================
// Live reload — watchBinary
// =============================================================================

// Modifying a watched file triggers an opRestart on the ops channel.
func TestWatchBinary_DetectsChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, err := os.CreateTemp("", "watchtest")
		if err != nil {
			t.Fatal(err)
		}
		path := f.Name()
		defer os.Remove(path)
		f.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ops := make(chan sessionOp, 1)

		app := NewApp(nil, pubsub.NewPubSub())
		go watchBinary(ctx, path, ops, app)

		// Wait for at least one poll cycle, then change the file's mod time
		time.Sleep(200 * time.Millisecond)
		now := time.Now().Add(time.Second)
		os.Chtimes(path, now, now)

		select {
		case op := <-ops:
			assert.Equal(t, op.kind, opRestart)
			op.reply <- sessionResult{} // unblock watchBinary
		case <-time.After(2 * time.Second):
			t.Error("timeout waiting for restart op after file change")
		}
	})
}

// =============================================================================
// Session proxy — nested calls
// =============================================================================

// Nested tool calls through sessionProxy complete without deadlocking.
// This regression test verifies that the event loop dispatches CallTool
// in goroutines (as runSession does), so a tool whose MCP handler calls
// back into the host doesn't block the event loop.
func TestSessionProxy_NestedCallsDoNotDeadlock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ops := make(chan sessionOp)
		proxy := &sessionProxy{ops: ops, ctx: ctx}

		// Mirror runSession's event loop: dispatch CallTool in goroutines.
		go func() {
			for {
				select {
				case op := <-ops:
					if op.kind == opCallTool {
						go func() {
							if op.callToolName == "outer" {
								// Simulate MCP server tool handler calling back
								// through the proxy (the nested call).
								inner, err := proxy.CallTool("inner", nil)
								if err != nil {
									op.reply <- sessionResult{err: err}
									return
								}
								op.reply <- sessionResult{data: inner}
							} else {
								// Inner tool: reply immediately.
								data, _ := json.Marshal(map[string]string{"tool": op.callToolName})
								op.reply <- sessionResult{data: data}
							}
						}()
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		// Outer call — would deadlock if the event loop ran CallTool synchronously.
		result, err := proxy.CallTool("outer", nil)
		if err != nil {
			t.Fatalf("outer CallTool: %v", err)
		}

		var got map[string]string
		json.Unmarshal(result, &got)
		assert.Equal(t, got["tool"], "inner")
	})
}

// Cancelling the context causes watchBinary to exit promptly.
func TestWatchBinary_StopsOnContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, err := os.CreateTemp("", "watchtest")
		if err != nil {
			t.Fatal(err)
		}
		path := f.Name()
		defer os.Remove(path)
		f.Close()

		ctx, cancel := context.WithCancel(context.Background())
		ops := make(chan sessionOp)

		app := NewApp(nil, pubsub.NewPubSub())
		done := make(chan struct{})
		go func() {
			watchBinary(ctx, path, ops, app)
			close(done)
		}()

		cancel()

		select {
		case <-done:
			// Good — exited promptly
		case <-time.After(time.Second):
			t.Error("watchBinary did not stop after context cancellation")
		}
	})
}
