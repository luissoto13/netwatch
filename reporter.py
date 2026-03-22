from flask import Flask, render_template_string, jsonify
from database import initialize_db, get_recent_alerts, get_alert_counts, get_connection, clear_alerts
from config import DASHBOARD_PORT

initialize_db()

app = Flask(__name__)


def get_alerts_over_time():
    conn = get_connection()
    rows = conn.execute("""
        SELECT strftime('%H:%M', detected_at) as time_bucket, COUNT(*) as count
        FROM alerts
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        LIMIT 20
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_top_offenders():
    conn = get_connection()
    rows = conn.execute("""
        SELECT src_ip, COUNT(*) as alert_count,
               SUM(CASE WHEN severity = 'HIGH'   THEN 1 ELSE 0 END) as high,
               SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
               SUM(CASE WHEN severity = 'LOW'    THEN 1 ELSE 0 END) as low
        FROM alerts
        GROUP BY src_ip
        ORDER BY alert_count DESC
        LIMIT 10
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_type_breakdown():
    conn = get_connection()
    rows = conn.execute("""
        SELECT alert_type, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetWatch</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }

        .header {
            display: flex;
            align-items: baseline;
            gap: 0.75rem;
            margin-bottom: 0.25rem;
        }

        .header h1 {
            font-size: 1.6rem;
            color: #00d4ff;
            letter-spacing: 0.04em;
        }

        .header .tagline {
            font-size: 0.78rem;
            color: #8b949e;
            border-left: 1px solid #30363d;
            padding-left: 0.75rem;
        }

        .subtitle {
            font-size: 0.8rem;
            color: #8b949e;
            margin-bottom: 1.75rem;
        }

        /* Last updated pill */
        .last-updated {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.72rem;
            color: #8b949e;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 999px;
            padding: 0.2rem 0.65rem;
            margin-left: 0.5rem;
            vertical-align: middle;
        }

        .last-updated .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #3fb950;
            flex-shrink: 0;
        }

        .stats {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.75rem;
            flex-wrap: wrap;
        }

        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem 1.5rem;
            min-width: 140px;
        }

        .stat-card .label {
            font-size: 0.72rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .stat-card .value {
            font-size: 1.8rem;
            font-weight: bold;
            color: #f0f6fc;
            margin-top: 0.2rem;
        }

        .stat-card.high   .value { color: #f85149; }
        .stat-card.medium .value { color: #e3b341; }
        .stat-card.low    .value { color: #3fb950; }

        .charts-row {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1rem;
            margin-bottom: 1.75rem;
        }

        .chart-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
        }

        .chart-card h3 {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #8b949e;
            margin-bottom: 1rem;
            font-weight: 400;
        }

        .chart-container {
            position: relative;
            height: 200px;
        }

        .bottom-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1.75rem;
        }

        .section-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
        }

        .section-card h3 {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #8b949e;
            margin-bottom: 1rem;
            font-weight: 400;
        }

        table { width: 100%; border-collapse: collapse; }

        th {
            text-align: left;
            padding: 0.5rem 0.75rem;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #8b949e;
            font-weight: 400;
            border-bottom: 1px solid #30363d;
        }

        td {
            padding: 0.6rem 0.75rem;
            font-size: 0.82rem;
            border-bottom: 1px solid #21262d;
        }

        tbody tr:last-child td { border-bottom: none; }

        .row-HIGH   { border-left: 3px solid #f85149; }
        .row-MEDIUM { border-left: 3px solid #e3b341; }
        .row-LOW    { border-left: 3px solid #3fb950; }

        tbody tr:hover td { background: #1c2128; }

        .mono { font-family: 'Courier New', monospace; font-size: 0.78rem; }

        .badge {
            display: inline-block;
            padding: 0.18rem 0.5rem;
            border-radius: 999px;
            font-size: 0.68rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.HIGH   { background: #3d1a1a; color: #f85149; }
        .badge.MEDIUM { background: #2d2200; color: #e3b341; }
        .badge.LOW    { background: #0d2116; color: #3fb950; }

        .empty {
            text-align: center;
            padding: 2rem;
            color: #8b949e;
            font-size: 0.85rem;
        }

        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .toolbar select {
            background: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.3rem 0.6rem;
            font-size: 0.8rem;
            cursor: pointer;
        }

        .toolbar-buttons {
            display: flex;
            gap: 0.5rem;
        }

        .refresh-btn {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.3rem 0.8rem;
            font-size: 0.8rem;
            cursor: pointer;
        }

        .refresh-btn:hover { background: #30363d; }

        /* Clear Alerts button — destructive styling */
        .clear-btn {
            background: #3d1a1a;
            color: #f85149;
            border: 1px solid #6e2020;
            border-radius: 6px;
            padding: 0.3rem 0.8rem;
            font-size: 0.8rem;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
        }

        .clear-btn:hover {
            background: #5a2020;
            border-color: #f85149;
        }

        .table-wrap {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 1.75rem;
        }

        .note {
            font-size: 0.72rem;
            color: #8b949e;
            text-align: right;
        }

        .pulse {
            display: inline-block;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #3fb950;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%   { opacity: 1; }
            50%  { opacity: 0.3; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>

<div class="header">
    <h1>NetWatch</h1>
    <span class="tagline"><span class="pulse"></span>Live network intrusion detection</span>
</div>
<p class="subtitle">
    Network Intrusion Detection System — auto-refreshes every 10 seconds
    <span class="last-updated">
        <span class="dot"></span>
        Last updated: <span id="last-updated-time">just now</span>
    </span>
</p>

<div class="stats">
    <div class="stat-card">
        <div class="label">Total alerts</div>
        <div class="value" id="count-total">{{ counts.TOTAL }}</div>
    </div>
    <div class="stat-card high">
        <div class="label">High severity</div>
        <div class="value" id="count-high">{{ counts.HIGH }}</div>
    </div>
    <div class="stat-card medium">
        <div class="label">Medium severity</div>
        <div class="value" id="count-medium">{{ counts.MEDIUM }}</div>
    </div>
    <div class="stat-card low">
        <div class="label">Low severity</div>
        <div class="value" id="count-low">{{ counts.LOW }}</div>
    </div>
</div>

<div class="charts-row">
    <div class="chart-card">
        <h3>Alerts over time</h3>
        <div class="chart-container">
            <canvas id="lineChart"></canvas>
        </div>
    </div>
    <div class="chart-card">
        <h3>Alert type breakdown</h3>
        <div class="chart-container">
            <canvas id="donutChart"></canvas>
        </div>
    </div>
</div>

<div class="bottom-row">
    <div class="section-card">
        <h3>Top offenders</h3>
        <table>
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Total</th>
                    <th>High</th>
                    <th>Med</th>
                    <th>Low</th>
                </tr>
            </thead>
            <tbody id="offenders-body">
                {% if offenders %}
                    {% for o in offenders %}
                    <tr>
                        <td class="mono">{{ o.src_ip }}</td>
                        <td>{{ o.alert_count }}</td>
                        <td style="color:#f85149;">{{ o.high }}</td>
                        <td style="color:#e3b341;">{{ o.medium }}</td>
                        <td style="color:#3fb950;">{{ o.low }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr><td colspan="5" class="empty">No data yet.</td></tr>
                {% endif %}
            </tbody>
        </table>
    </div>

    <div class="section-card">
        <h3>Filters</h3>
        <div class="toolbar">
            <select id="severity-filter" onchange="applyFilter()">
                <option value="ALL">All severities</option>
                <option value="HIGH">High only</option>
                <option value="MEDIUM">Medium only</option>
                <option value="LOW">Low only</option>
            </select>
            <div class="toolbar-buttons">
                <button class="refresh-btn" onclick="refreshData()">Refresh now</button>
                <button class="clear-btn" onclick="clearAlerts()">Clear alerts</button>
            </div>
        </div>
    </div>
</div>

<div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Alert type</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody id="alert-table-body">
            {% if alerts %}
                {% for a in alerts %}
                <tr class="row-{{ a.severity }}" data-severity="{{ a.severity }}">
                    <td class="mono">{{ a.detected_at }}</td>
                    <td>{{ a.alert_type }}</td>
                    <td><span class="badge {{ a.severity }}">{{ a.severity }}</span></td>
                    <td class="mono">{{ a.src_ip }}</td>
                    <td class="mono">{{ a.dst_ip or 'N/A' }}</td>
                    <td>{{ a.description or 'N/A' }}</td>
                </tr>
                {% endfor %}
            {% else %}
                <tr><td colspan="6" class="empty">No alerts yet. Start main.py to begin monitoring.</td></tr>
            {% endif %}
        </tbody>
    </table>
</div>

<p class="note">Showing the 50 most recent alerts.</p>

<script>
const DONUT_COLORS = ['#f85149','#e3b341','#3fb950','#00d4ff','#a371f7'];

const lineCtx  = document.getElementById('lineChart').getContext('2d');
const donutCtx = document.getElementById('donutChart').getContext('2d');

const initTimeline  = {{ timeline  | tojson }};
const initBreakdown = {{ breakdown | tojson }};

let lineChart = new Chart(lineCtx, {
    type: 'line',
    data: {
        labels: initTimeline.map(d => d.time_bucket),
        datasets: [{
            label: 'Alerts',
            data: initTimeline.map(d => d.count),
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0,212,255,0.08)',
            borderWidth: 2,
            pointBackgroundColor: '#00d4ff',
            pointRadius: 3,
            tension: 0.4,
            fill: true
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e', font: { size: 10 }, stepSize: 1 }, grid: { color: '#21262d' }, beginAtZero: true }
        }
    }
});

let donutChart = new Chart(donutCtx, {
    type: 'doughnut',
    data: {
        labels: initBreakdown.map(d => d.alert_type),
        datasets: [{
            data: initBreakdown.map(d => d.count),
            backgroundColor: DONUT_COLORS.slice(0, initBreakdown.length),
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 10, padding: 10 }
            }
        },
        cutout: '65%'
    }
});

function updateLastUpdatedTime() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    document.getElementById('last-updated-time').textContent = timeStr;
}

function applyFilter() {
    const val = document.getElementById('severity-filter').value;
    document.querySelectorAll('#alert-table-body tr[data-severity]').forEach(row => {
        row.style.display = (val === 'ALL' || row.dataset.severity === val) ? '' : 'none';
    });
}

function refreshData() {
    fetch('/api/alerts')
        .then(r => r.json())
        .then(data => {
            document.getElementById('count-total').textContent  = data.counts.TOTAL;
            document.getElementById('count-high').textContent   = data.counts.HIGH;
            document.getElementById('count-medium').textContent = data.counts.MEDIUM;
            document.getElementById('count-low').textContent    = data.counts.LOW;

            const tbody = document.getElementById('alert-table-body');
            if (data.alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty">No alerts yet. Start main.py to begin monitoring.</td></tr>';
            } else {
                tbody.innerHTML = data.alerts.map(a => `
                    <tr class="row-${a.severity}" data-severity="${a.severity}">
                        <td class="mono">${a.detected_at}</td>
                        <td>${a.alert_type}</td>
                        <td><span class="badge ${a.severity}">${a.severity}</span></td>
                        <td class="mono">${a.src_ip}</td>
                        <td class="mono">${a.dst_ip || 'N/A'}</td>
                        <td>${a.description || 'N/A'}</td>
                    </tr>
                `).join('');
                applyFilter();
            }

            const offBody = document.getElementById('offenders-body');
            if (data.offenders.length === 0) {
                offBody.innerHTML = '<tr><td colspan="5" class="empty">No data yet.</td></tr>';
            } else {
                offBody.innerHTML = data.offenders.map(o => `
                    <tr>
                        <td class="mono">${o.src_ip}</td>
                        <td>${o.alert_count}</td>
                        <td style="color:#f85149;">${o.high}</td>
                        <td style="color:#e3b341;">${o.medium}</td>
                        <td style="color:#3fb950;">${o.low}</td>
                    </tr>
                `).join('');
            }

            lineChart.data.labels = data.timeline.map(d => d.time_bucket);
            lineChart.data.datasets[0].data = data.timeline.map(d => d.count);
            lineChart.update();

            donutChart.data.labels = data.breakdown.map(d => d.alert_type);
            donutChart.data.datasets[0].data = data.breakdown.map(d => d.count);
            donutChart.data.datasets[0].backgroundColor = DONUT_COLORS.slice(0, data.breakdown.length);
            donutChart.update();

            // Stamp the refresh time
            updateLastUpdatedTime();
        });
}

function clearAlerts() {
    if (!confirm('Clear all alerts from the database? This cannot be undone.')) return;
    fetch('/api/clear', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.status === 'ok') {
                refreshData();
            }
        });
}

// Set initial timestamp on page load
updateLastUpdatedTime();

setInterval(refreshData, 10000);
</script>

</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(
        DASHBOARD_TEMPLATE,
        alerts=get_recent_alerts(),
        counts=get_alert_counts(),
        offenders=get_top_offenders(),
        timeline=get_alerts_over_time(),
        breakdown=get_alert_type_breakdown()
    )


@app.route("/api/alerts")
def api_alerts():
    return jsonify({
        "alerts":    get_recent_alerts(),
        "counts":    get_alert_counts(),
        "offenders": get_top_offenders(),
        "timeline":  get_alerts_over_time(),
        "breakdown": get_alert_type_breakdown()
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_alerts()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print(f"[NETWATCH] Running at http://127.0.0.1:{DASHBOARD_PORT}")
    app.run(debug=True, port=DASHBOARD_PORT)