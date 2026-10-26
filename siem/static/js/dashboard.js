/* Mini-SIEM dashboard: fetches /api/stats and renders KPIs, charts and tables.
 * All text is inserted with textContent, never innerHTML, so log data cannot inject markup. */
(function () {
  "use strict";

  const script = document.currentScript;
  const STATS_URL = script.dataset.statsUrl;
  const ALERT_URL = script.dataset.alertUrl;
  const EVENTS_URL = script.dataset.eventsUrl;

  const SEVERITY_COLORS = { critical: "#e5484d", high: "#f5a524", medium: "#3e9bff", low: "#8b8d98" };
  const SERIES_COLORS = {
    "Web requests": "#3e9bff",
    "Failed logins": "#e5484d",
    "Successful logins": "#30a46c",
    "New alerts": "#f5a524",
  };
  const PALETTE = ["#3e9bff", "#30a46c", "#f5a524", "#e5484d", "#8e4ec6", "#12a594", "#d6409f", "#8b8d98"];
  const nf = new Intl.NumberFormat();

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === "class") node.className = v; else node.setAttribute(k, v);
    });
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function severityBadge(severity) {
    const classes = { critical: "danger", high: "warning", medium: "info", low: "secondary" };
    return el("span", { class: `badge sev-badge text-bg-${classes[severity] || "secondary"}` }, severity || "–");
  }

  function emptyRow(tbody, cols, message) {
    const tr = el("tr");
    tr.appendChild(el("td", { colspan: cols, class: "text-body-secondary text-center py-3" }, message));
    tbody.appendChild(tr);
  }

  function renderKpis(kpis) {
    document.querySelectorAll("[data-kpi]").forEach((node) => {
      const value = kpis[node.dataset.kpi];
      node.textContent = value === undefined || value === null ? "–" : nf.format(value);
    });
    const range = document.getElementById("data-range");
    range.textContent = kpis.first_event
      ? `Data from ${kpis.first_event} to ${kpis.last_event} UTC · ${nf.format(kpis.files_ingested)} file(s) ingested · ${nf.format(kpis.total_alerts)} alert(s)`
      : "No data ingested yet.";
    document.getElementById("empty-state").classList.toggle("d-none", kpis.total_events > 0);
  }

  function renderTopIps(rows) {
    const tbody = document.getElementById("top-ips");
    tbody.replaceChildren();
    if (!rows.length) return emptyRow(tbody, 5, "No source IPs yet.");
    rows.forEach((row) => {
      const tr = el("tr");
      const ipCell = el("td");
      const link = el("a", { href: `${EVENTS_URL}?source_ip=${encodeURIComponent(row.source_ip)}`, class: "mono" }, row.source_ip);
      ipCell.appendChild(link);
      if (row.worst_severity) { ipCell.append(" "); ipCell.appendChild(severityBadge(row.worst_severity)); }
      tr.appendChild(ipCell);
      tr.appendChild(el("td", { class: "text-end" }, nf.format(row.events)));
      tr.appendChild(el("td", { class: "text-end" }, nf.format(row.failed_logins)));
      tr.appendChild(el("td", { class: "text-end" }, nf.format(row.http_errors)));
      const alertsCell = el("td", { class: "text-end" });
      if (row.alerts) {
        alertsCell.appendChild(el("a", { href: `${ALERT_URL}?source_ip=${encodeURIComponent(row.source_ip)}` }, String(row.alerts)));
      } else {
        alertsCell.textContent = "0";
      }
      tr.appendChild(alertsCell);
      tbody.appendChild(tr);
    });
  }

  function renderRecentAlerts(rows) {
    const tbody = document.getElementById("recent-alerts");
    tbody.replaceChildren();
    if (!rows.length) return emptyRow(tbody, 4, "No alerts. Ingest logs and run detection.");
    const statusLabels = { open: "Open", investigating: "Investigating", resolved: "Resolved", false_positive: "False positive" };
    rows.forEach((row) => {
      const tr = el("tr");
      const sev = el("td"); sev.appendChild(severityBadge(row.severity)); tr.appendChild(sev);
      const title = el("td");
      title.appendChild(el("a", { href: `${ALERT_URL}/${row.id}` }, row.title));
      title.appendChild(el("div", { class: "small text-body-secondary" }, row.rule_name));
      tr.appendChild(title);
      tr.appendChild(el("td", { class: "mono small" }, row.last_seen));
      tr.appendChild(el("td", { class: "small" }, statusLabels[row.status] || row.status));
      tbody.appendChild(tr);
    });
  }

  function chartDefaults() {
    const styles = getComputedStyle(document.body);
    Chart.defaults.color = styles.getPropertyValue("--bs-secondary-color").trim() || "#9ba1a6";
    Chart.defaults.borderColor = styles.getPropertyValue("--siem-grid").trim() || "rgba(255,255,255,0.08)";
    Chart.defaults.font.family = styles.getPropertyValue("--bs-body-font-family");
    Chart.defaults.maintainAspectRatio = false;
    Chart.defaults.plugins.legend.labels.boxWidth = 12;
  }

  function renderCharts(data) {
    const timeline = data.timeline;
    document.getElementById("bucket-label").textContent = timeline.bucket ? `per ${timeline.bucket} bucket` : "";
    new Chart(document.getElementById("chart-timeline"), {
      type: "line",
      data: {
        labels: timeline.labels,
        datasets: Object.entries(timeline.series).map(([name, values]) => ({
          label: name,
          data: values,
          borderColor: SERIES_COLORS[name],
          backgroundColor: SERIES_COLORS[name],
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.25,
          yAxisID: name === "Web requests" ? "y" : "y2",
        })),
      },
      options: {
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { ticks: { maxTicksLimit: 12 } },
          y: { beginAtZero: true, title: { display: true, text: "Web requests" } },
          y2: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false },
                title: { display: true, text: "Logins / alerts" } },
        },
      },
    });

    const sev = data.alerts.by_severity;
    new Chart(document.getElementById("chart-severity"), {
      type: "doughnut",
      data: {
        labels: Object.keys(sev),
        datasets: [{ data: Object.values(sev), backgroundColor: Object.keys(sev).map((s) => SEVERITY_COLORS[s]), borderWidth: 0 }],
      },
      options: { cutout: "62%", plugins: { legend: { position: "bottom" } } },
    });

    const rules = data.alerts.by_rule;
    new Chart(document.getElementById("chart-rules"), {
      type: "bar",
      data: { labels: Object.keys(rules), datasets: [{ label: "Alerts", data: Object.values(rules), backgroundColor: "#3e9bff", borderRadius: 4 }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } },
    });

    const http = data.http_status;
    const httpColors = Object.keys(http).map((code) =>
      code.startsWith("2") ? "#30a46c" : code.startsWith("3") ? "#8b8d98" : code.startsWith("4") ? "#f5a524" : "#e5484d");
    new Chart(document.getElementById("chart-http"), {
      type: "bar",
      data: { labels: Object.keys(http), datasets: [{ label: "Responses", data: Object.values(http), backgroundColor: httpColors, borderRadius: 4 }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { type: "logarithmic", title: { display: true, text: "count (log)" } } } },
    });

    const types = data.event_types;
    new Chart(document.getElementById("chart-types"), {
      type: "doughnut",
      data: { labels: Object.keys(types), datasets: [{ data: Object.values(types), backgroundColor: PALETTE, borderWidth: 0 }] },
      options: { cutout: "62%", plugins: { legend: { position: "bottom" } } },
    });
  }

  fetch(STATS_URL, { headers: { Accept: "application/json" } })
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then((data) => {
      renderKpis(data.kpis);
      renderTopIps(data.top_ips);
      renderRecentAlerts(data.recent_alerts);
      if (typeof window.Chart === "undefined") {
        document.getElementById("chart-warning").classList.remove("d-none");
        return;
      }
      chartDefaults();
      renderCharts(data);
    })
    .catch((error) => {
      document.getElementById("data-range").textContent = `Could not load dashboard data (${error.message}).`;
    });
})();
