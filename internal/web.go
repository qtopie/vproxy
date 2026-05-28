package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	webMemoryTrace *MemoryTraceFormatter
	webConfigPath  string
	webApp         *App
)

// StartWebServer starts the management Web UI.
func StartWebServer(app *App, mtf *MemoryTraceFormatter) {
	webApp = app
	webConfigPath = app.ConfigPath
	webMemoryTrace = mtf

	http.HandleFunc("/api/traces", handleTraces)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/", handleIndex)

	Infof("Web UI started on http://127.0.0.1:%d", app.Config.WebPort)
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", app.Config.WebPort), nil); err != nil {
			Errorf("Web UI server failed: %v", err)
		}
	}()
}

func handleTraces(w http.ResponseWriter, r *http.Request) {
	if webMemoryTrace == nil {
		http.Error(w, "Trace system not initialized", 500)
		return
	}
	traces := webMemoryTrace.GetTraces()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(traces)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webApp.Config)
		return
	}

	if r.Method == http.MethodPost {
		var newCfg Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// Save to file
		data, err := json.MarshalIndent(newCfg, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		if err := os.WriteFile(webConfigPath, data, 0644); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save config: %v", err), 500)
			return
		}

		// Hot update running config
		webApp.Config = &newCfg
		// Update components
		ph := webApp.getProxyHandler()
		if ph != nil {
			ph.UpdateRules(newCfg.Rules, newCfg.DirectDNS == nil || *newCfg.DirectDNS)
			ph.UpdateServers(newCfg.Upstreams)
		}

		w.Write([]byte("Config saved and applied"))
		return
	}

	http.Error(w, "Method not allowed", 405)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, indexHTML)
}

const indexHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>vproxy Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; display: flex; height: 100vh; background: #f5f5f7; }
        #sidebar { width: 250px; background: #fff; border-right: 1px solid #ddd; padding: 20px; flex-shrink: 0; }
        #main { flex: 1; overflow-y: auto; padding: 20px; }
        h2 { margin-top: 0; }
        .nav-item { padding: 10px; cursor: pointer; border-radius: 5px; margin-bottom: 5px; }
        .nav-item:hover { background: #eee; }
        .nav-item.active { background: #007bff; color: white; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #fafafa; }
        .status-200 { color: #28a745; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        textarea { width: 100%; height: 400px; font-family: monospace; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; }
        button:hover { background: #0056b3; }
        .trace-detail { font-size: 12px; color: #666; white-space: pre-wrap; word-break: break-all; background: #f9f9f9; padding: 10px; display: none; margin-top: 10px; }
    </style>
</head>
<body>
    <div id="sidebar">
        <h2>vproxy</h2>
        <div class="nav-item active" onclick="showSection('traces')">HTTP Traces</div>
        <div class="nav-item" onclick="showSection('config')">Rules & Config</div>
    </div>
    <div id="main">
        <div id="traces-section">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2>HTTPS Deep Tracing</h2>
                <button onclick="loadTraces()">Refresh</button>
            </div>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Method</th>
                            <th>Host</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Latency</th>
                        </tr>
                    </thead>
                    <tbody id="trace-list"></tbody>
                </table>
            </div>
        </div>

        <div id="config-section" style="display: none;">
            <h2>Configuration</h2>
            <div class="card">
                <p>Edit your rules in JSON format (similar to config.json):</p>
                <textarea id="config-editor"></textarea>
                <div style="margin-top: 15px;">
                    <button onclick="saveConfig()">Save & Apply</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentSection = 'traces';

        function showSection(id) {
            document.getElementById(currentSection + '-section').style.display = 'none';
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            
            currentSection = id;
            document.getElementById(id + '-section').style.display = 'block';
            event.target.classList.add('active');

            if (id === 'traces') loadTraces();
            if (id === 'config') loadConfig();
        }

        async function loadTraces() {
            const resp = await fetch('/api/traces');
            const traces = await resp.json();
            const list = document.getElementById('trace-list');
            list.innerHTML = '';
            
            traces.reverse().forEach(t => {
                const tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.onclick = () => toggleDetail(t.id);
                
                const statusClass = t.status_code >= 400 ? 'status-error' : 'status-200';
                
                tr.innerHTML = '<td><b>' + t.method + '</b></td>' +
                               '<td>' + t.host + '</td>' +
                               '<td>' + t.path + '</td>' +
                               '<td class="' + statusClass + '">' + t.status_code + '</td>' +
                               '<td>' + t.latency_ms.toFixed(1) + 'ms</td>';
                
                const detailRow = document.createElement('tr');
                detailRow.innerHTML = '<td colspan="5" style="padding: 0; border: none;">' +
                                      '<div id="detail-' + t.id + '" class="trace-detail">' +
                                      '<b>Request Headers:</b><br>' + JSON.stringify(t.req_headers, null, 2) + '<br><br>' +
                                      '<b>Request Body:</b><br>' + (t.req_body || '(empty)') + '<br><br>' +
                                      '<b>Response Headers:</b><br>' + JSON.stringify(t.resp_headers, null, 2) + '<br><br>' +
                                      '<b>Response Body:</b><br>' + (t.resp_body || '(empty)') +
                                      '</div></td>';
                
                list.appendChild(tr);
                list.appendChild(detailRow);
            });
        }

        function toggleDetail(id) {
            const el = document.getElementById('detail-' + id);
            el.style.display = el.style.display === 'block' ? 'none' : 'block';
        }

        async function loadConfig() {
            const resp = await fetch('/api/config');
            const config = await resp.json();
            document.getElementById('config-editor').value = JSON.stringify(config, null, 2);
        }

        async function saveConfig() {
            const val = document.getElementById('config-editor').value;
            try {
                const config = JSON.parse(val);
                const resp = await fetch('/api/config', {
                    method: 'POST',
                    body: JSON.stringify(config)
                });
                if (resp.ok) alert('Config saved successfully!');
                else alert('Error: ' + await resp.text());
            } catch (e) {
                alert('Invalid JSON: ' + e.message);
            }
        }

        // Auto-refresh traces
        setInterval(() => {
            if (currentSection === 'traces') loadTraces();
        }, 5000);

        loadTraces();
    </script>
</body>
</html>
`
