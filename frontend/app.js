/**
 * HoneyTrap Frontend Application
 * Real-time WebSocket event ingestion, Leaflet attack mapping, and Chart.js analytics.
 */

document.addEventListener("DOMContentLoaded", () => {
    // State
    let threatMap = null;
    let mapMarkers = [];
    let mitreChart = null;
    let protocolChart = null;
    let attackersChart = null;
    let ws = null;
    let eventsCount = 0;
    let allIocs = [];

    // DOM Elements
    const statTotalEvents = document.getElementById("stat-total-events");
    const statEventsToday = document.getElementById("stat-events-today");
    const statTotalSessions = document.getElementById("stat-total-sessions");
    const statSessionsToday = document.getElementById("stat-sessions-today");
    const statUniqueIps = document.getElementById("stat-unique-ips");
    const statTotalIocs = document.getElementById("stat-total-iocs");
    const eventsTbody = document.getElementById("events-tbody");
    const iocsTbody = document.getElementById("iocs-tbody");
    const wsStatusText = document.getElementById("ws-status-text");
    const sessionSelect = document.getElementById("session-select");
    const terminalContent = document.getElementById("terminal-content");
    const btnRefreshSessions = document.getElementById("btn-refresh-sessions");
    const iocFilter = document.getElementById("ioc-filter");

    // Initialize Leaflet Map
    function initMap() {
        threatMap = L.map("threat-map", {
            center: [25, 10],
            zoom: 2,
            minZoom: 1,
            maxZoom: 10,
        });

        L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
            maxZoom: 19,
        }).addTo(threatMap);
    }

    function addMapMarker(lat, lon, ip, protocol, country) {
        if (!lat || !lon || lat === 0 && lon === 0) return;
        
        let color = "#10b981"; // SSH green
        if (protocol === "http") color = "#3b82f6"; // HTTP blue
        if (protocol === "ftp") color = "#f59e0b"; // FTP orange

        const marker = L.circleMarker([lat, lon], {
            radius: 6,
            fillColor: color,
            color: "#fff",
            weight: 1,
            opacity: 0.9,
            fillOpacity: 0.7,
        }).addTo(threatMap);

        marker.bindPopup(`<b>${ip}</b><br>Protocol: ${protocol.toUpperCase()}<br>Location: ${country || 'Unknown'}`);
        mapMarkers.push(marker);

        if (mapMarkers.length > 100) {
            const old = mapMarkers.shift();
            threatMap.removeLayer(old);
        }
    }

    // Initialize Charts
    function initCharts() {
        // 1. MITRE ATT&CK Horizontal Bar Chart
        const mitreCtx = document.getElementById("mitreChart").getContext("2d");
        mitreChart = new Chart(mitreCtx, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Occurrences",
                    data: [],
                    backgroundColor: "rgba(139, 92, 246, 0.6)",
                    borderColor: "rgba(139, 92, 246, 1)",
                    borderWidth: 1,
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#9ca3af" } },
                    y: { grid: { display: false }, ticks: { color: "#d1d5db", font: { family: "monospace", size: 10 } } }
                }
            }
        });

        // 2. Protocol Doughnut Chart
        const protoCtx = document.getElementById("protocolChart").getContext("2d");
        protocolChart = new Chart(protoCtx, {
            type: "doughnut",
            data: {
                labels: ["SSH", "HTTP", "FTP"],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ["#10b981", "#3b82f6", "#f59e0b"],
                    borderWidth: 0,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { color: "#d1d5db", font: { family: "monospace" } } }
                }
            }
        });

        // 3. Top Attackers Bar Chart
        const attCtx = document.getElementById("attackersChart").getContext("2d");
        attackersChart = new Chart(attCtx, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Events",
                    data: [],
                    backgroundColor: "rgba(6, 182, 212, 0.6)",
                    borderColor: "rgba(6, 182, 212, 1)",
                    borderWidth: 1,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false }, ticks: { color: "#d1d5db", font: { family: "monospace", size: 9 } } },
                    y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#9ca3af" } }
                }
            }
        });
    }

    // Helper formatting
    function formatPayload(event) {
        const d = event.data || {};
        if (event.event_type === "auth_attempt") {
            const status = d.success ? "SUCCESS" : "FAILED";
            return `AUTH: ${d.username || 'unknown'} / ${d.password || '******'} [${status}]`;
        }
        if (event.event_type === "command") {
            return `$ ${d.command || ''}`;
        }
        if (event.event_type === "http_request") {
            return `${d.method || 'GET'} ${d.path || '/'}`;
        }
        if (event.event_type === "ftp_command") {
            return `FTP: ${d.raw_command || d.command || ''}`;
        }
        if (event.event_type === "file_upload") {
            return `UPLOAD: ${d.filename} (${d.size_bytes}B)`;
        }
        return d.message || event.event_type || "";
    }

    function addEventRow(event, prepend = true) {
        if (eventsCount === 0 && prepend) {
            eventsTbody.innerHTML = "";
        }
        eventsCount++;

        const tr = document.createElement("tr");
        const proto = (event.protocol || "sys").toLowerCase();
        const protoBadge = `<span class="proto-badge proto-${proto}">${proto.toUpperCase()}</span>`;

        const timeStr = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "--";
        const ipStr = event.source_ip || "127.0.0.1";
        const payloadStr = formatPayload(event);

        const mitreBadges = (event.mitre_techniques || [])
            .map(t => `<span class="tech-tag">${t}</span>`)
            .join("");

        tr.innerHTML = `
            <td>${timeStr}</td>
            <td>${protoBadge}</td>
            <td>${ipStr}</td>
            <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${payloadStr}</td>
            <td>${mitreBadges || '<span style="color:#6b7280;">—</span>'}</td>
        `;

        if (prepend) {
            eventsTbody.prepend(tr);
            if (eventsTbody.children.length > 80) {
                eventsTbody.removeChild(eventsTbody.lastChild);
            }
        } else {
            eventsTbody.appendChild(tr);
        }

        // Add to map if geo coordinates exist
        if (event.geo && event.geo.lat && event.geo.lon) {
            addMapMarker(event.geo.lat, event.geo.lon, ipStr, proto, event.geo.country);
        }
    }

    // Load initial data
    async function loadData() {
        try {
            // 1. Stats
            const resStats = await fetch("/api/stats");
            if (resStats.ok) {
                const s = await resStats.json();
                statTotalEvents.textContent = s.total_events.toLocaleString();
                statEventsToday.textContent = `${s.events_last_24h} in last 24h`;
                statTotalSessions.textContent = s.total_sessions.toLocaleString();
                statSessionsToday.textContent = `${s.sessions_last_24h} in last 24h`;
                statUniqueIps.textContent = s.unique_ips.toLocaleString();
                statTotalIocs.textContent = s.total_iocs.toLocaleString();

                // Protocol chart
                const p = s.protocol_breakdown || {};
                protocolChart.data.datasets[0].data = [p.ssh || 0, p.http || 0, p.ftp || 0];
                protocolChart.update();
            }

            // 2. Recent Events
            const resEvents = await fetch("/api/events?per_page=30");
            if (resEvents.ok) {
                const data = await resEvents.json();
                if (data.events && data.events.length > 0) {
                    eventsTbody.innerHTML = "";
                    data.events.forEach(e => addEventRow(e, false));
                }
            }

            // 3. MITRE Techniques
            const resMitre = await fetch("/api/mitre");
            if (resMitre.ok) {
                const techniques = await resMitre.json();
                mitreChart.data.labels = techniques.slice(0, 7).map(t => `${t.technique_id} ${t.name}`);
                mitreChart.data.datasets[0].data = techniques.slice(0, 7).map(t => t.count);
                mitreChart.update();
            }

            // 4. Top Attackers
            const resAttackers = await fetch("/api/attackers?limit=6");
            if (resAttackers.ok) {
                const attackers = await resAttackers.json();
                attackersChart.data.labels = attackers.map(a => a.source_ip);
                attackersChart.data.datasets[0].data = attackers.map(a => a.event_count);
                attackersChart.update();
            }

            // 5. IOCs
            await loadIOCs();

            // 6. Sessions
            await loadSessions();

        } catch (err) {
            console.error("Error loading dashboard data:", err);
        }
    }

    async function loadIOCs() {
        try {
            const res = await fetch("/api/iocs?limit=50");
            if (res.ok) {
                allIocs = await res.json();
                renderIOCs(allIocs);
            }
        } catch (err) {
            console.error("Error loading IOCs:", err);
        }
    }

    function renderIOCs(iocs) {
        if (!iocs || iocs.length === 0) {
            iocsTbody.innerHTML = `<tr class="empty-row"><td colspan="5">No IOCs extracted yet</td></tr>`;
            return;
        }

        iocsTbody.innerHTML = "";
        iocs.forEach(ioc => {
            const tr = document.createElement("tr");
            const conf = Math.round((ioc.confidence || 1.0) * 100);
            const firstSeen = ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : "--";
            const lastSeen = ioc.last_seen ? new Date(ioc.last_seen).toLocaleTimeString() : "--";
            tr.innerHTML = `
                <td><span class="panel-badge">${ioc.type.toUpperCase()}</span></td>
                <td style="color:#38bdf8;">${ioc.value}</td>
                <td>${conf}%</td>
                <td>${firstSeen}</td>
                <td>${lastSeen}</td>
            `;
            iocsTbody.appendChild(tr);
        });
    }

    iocFilter.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        if (!query) {
            renderIOCs(allIocs);
        } else {
            const filtered = allIocs.filter(i => 
                i.type.toLowerCase().includes(query) || i.value.toLowerCase().includes(query)
            );
            renderIOCs(filtered);
        }
    });

    async function loadSessions() {
        try {
            const res = await fetch("/api/sessions?per_page=20");
            if (res.ok) {
                const data = await res.json();
                sessionSelect.innerHTML = `<option value="">-- Choose Session to Replay --</option>`;
                (data.sessions || []).forEach(s => {
                    const opt = document.createElement("option");
                    opt.value = s.id;
                    opt.textContent = `[${s.protocol.toUpperCase()}] ${s.source_ip} (${s.events_count} events)`;
                    sessionSelect.appendChild(opt);
                });
            }
        } catch (err) {
            console.error("Error loading sessions:", err);
        }
    }

    sessionSelect.addEventListener("change", async (e) => {
        const sid = e.target.value;
        if (!sid) {
            terminalContent.textContent = "Select an active or historical SSH session above to review command interactions.";
            return;
        }

        terminalContent.textContent = "Loading session interaction details...";
        try {
            const res = await fetch(`/api/sessions/${sid}`);
            if (res.ok) {
                const s = await res.json();
                let output = `Session ID: ${s.id}\n`;
                output += `Source IP:  ${s.source_ip}:${s.source_port}\n`;
                output += `Protocol:   ${s.protocol.toUpperCase()}\n`;
                output += `Started:    ${s.start_time}\n`;
                output += `--------------------------------------------------\n`;

                if (s.asciicast) {
                    output += `\n[ASCIICAST TERMINAL REPLAY AVAILABLE]\n`;
                    // Parse raw lines
                    const lines = s.asciicast.trim().split("\n");
                    lines.forEach((l, idx) => {
                        if (idx === 0) return;
                        try {
                            const entry = JSON.parse(l);
                            if (entry[1] === "o" || entry[1] === "i") {
                                output += entry[2];
                            }
                        } catch (err) {}
                    });
                } else if (s.events && s.events.length > 0) {
                    s.events.forEach(ev => {
                        output += `[${new Date(ev.timestamp).toLocaleTimeString()}] ${formatPayload(ev)}\n`;
                    });
                } else {
                    output += "No commands or interaction logs recorded for this session.";
                }

                terminalContent.textContent = output;
            }
        } catch (err) {
            terminalContent.textContent = "Failed to load session details.";
        }
    });

    btnRefreshSessions.addEventListener("click", loadSessions);

    // WebSocket real-time connection
    function connectWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws/events`;

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            wsStatusText.textContent = "CONNECTED (LIVE)";
            wsStatusText.style.color = "#10b981";
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                addEventRow(data, true);

                // Increment total events counter
                const curr = parseInt(statTotalEvents.textContent.replace(/,/g, ""), 10) || 0;
                statTotalEvents.textContent = (curr + 1).toLocaleString();
            } catch (err) {
                console.error("WS parse error:", err);
            }
        };

        ws.onclose = () => {
            wsStatusText.textContent = "RECONNECTING";
            wsStatusText.style.color = "#f59e0b";
            setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (err) => {
            ws.close();
        };
    }

    // Startup
    initMap();
    initCharts();
    loadData();
    connectWebSocket();
});
