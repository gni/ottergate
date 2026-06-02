package controlplane

const DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ottergate — control plane</title>
    <style>
        :root {
            /* Standard system font families */
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, "Liberation Mono", monospace;

            /* Light theme variables */
            --bg-base: #f8fafc;
            --bg-card: #ffffff;
            --bg-muted: #f1f5f9;
            --border-color: #e2e8f0;
            --text-main: #0f172a;
            --text-muted: #64748b;
            
            --destructive: #ef4444;
            --destructive-hover: #dc2626;
            --info: #3b82f6;

            --radius: 6px;

            /* Theme dynamic colors */
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-glow: rgba(37, 99, 235, 0.15);
        }

        :root[data-color="blue"] {
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --primary-glow: rgba(37, 99, 235, 0.15);
        }
        :root[data-color="emerald"] {
            --primary: #059669;
            --primary-hover: #047857;
            --primary-glow: rgba(5, 150, 105, 0.15);
        }
        :root[data-color="violet"] {
            --primary: #7c3aed;
            --primary-hover: #6d28d9;
            --primary-glow: rgba(124, 58, 237, 0.15);
        }
        :root[data-color="orange"] {
            --primary: #ea580c;
            --primary-hover: #c2410c;
            --primary-glow: rgba(234, 88, 12, 0.15);
        }

        .dark {
            /* Dark theme variables */
            --bg-base: #070a13;
            --bg-card: #0e1322;
            --bg-muted: #161c2e;
            --border-color: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            
            --destructive: #f87171;
            --destructive-hover: #ef4444;
            --info: #60a5fa;

            --primary: #3b82f6;
            --primary-hover: #60a5fa;
            --primary-glow: rgba(59, 130, 246, 0.25);
        }

        .dark[data-color="blue"] {
            --primary: #3b82f6;
            --primary-hover: #60a5fa;
            --primary-glow: rgba(59, 130, 246, 0.25);
        }
        .dark[data-color="emerald"] {
            --primary: #10b981;
            --primary-hover: #34d399;
            --primary-glow: rgba(16, 185, 129, 0.25);
        }
        .dark[data-color="violet"] {
            --primary: #a78bfa;
            --primary-hover: #c084fc;
            --primary-glow: rgba(167, 139, 250, 0.25);
        }
        .dark[data-color="orange"] {
            --primary: #fb923c;
            --primary-hover: #fdba74;
            --primary-glow: rgba(251, 146, 60, 0.25);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-sans);
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            overflow: hidden;
            font-size: 13px;
            transition: background-color 0.15s, color 0.15s;
        }

        /* App Layout Frame */
        .app-frame {
            display: flex;
            width: 100vw;
            height: 100vh;
            overflow: hidden;
        }

        /* Sidebar navigation */
        .sidebar {
            width: 250px;
            display: flex;
            flex-direction: column;
            height: 100%;
            border-right: 1px solid var(--border-color);
            background-color: var(--bg-card);
            flex-shrink: 0;
        }

        .brand-section {
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            border-bottom: 1px solid var(--border-color);
        }

        .brand-title {
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-main);
        }

        .brand-desc {
            font-size: 10px;
            color: var(--text-muted);
            text-transform: lowercase;
            font-weight: 500;
            letter-spacing: 0.05em;
        }

        .theme-toggle-container {
            margin-top: 10px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .theme-btn {
            background-color: var(--bg-muted);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 5px 10px;
            cursor: pointer;
            color: var(--text-main);
            font-size: 11px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
            width: 100%;
            justify-content: center;
            text-transform: lowercase;
            user-select: none;
        }

        .theme-btn:hover {
            background-color: var(--border-color);
        }

        .color-dot.active {
            border-color: var(--text-main) !important;
            transform: scale(1.15);
        }

        .index-menu {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .index-label {
            font-size: 10px;
            text-transform: lowercase;
            color: var(--text-muted);
            font-weight: 700;
            padding: 16px 20px 8px 20px;
            letter-spacing: 0.05em;
        }

        .index-list {
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            flex: 1;
        }

        .index-item {
            cursor: pointer;
            display: flex;
            flex-direction: column;
            gap: 4px;
            color: var(--text-muted);
            user-select: none;
            padding: 10px 20px;
            border-bottom: 1px solid var(--border-color);
            background: transparent;
            transition: background-color 0.1s, color 0.1s;
        }

        .index-item:hover {
            color: var(--text-main);
            background-color: var(--bg-muted);
        }

        .index-item.active {
            color: var(--text-main);
            background-color: var(--bg-muted);
        }

        .index-header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .index-name {
            font-size: 12px;
            font-weight: 600;
            text-transform: lowercase;
        }

        .index-ip-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .index-ip {
            font-family: var(--font-mono);
            font-size: 11px;
        }

        .index-network-tag {
            font-size: 9px;
            font-weight: 600;
            text-transform: lowercase;
            border: 1px solid var(--border-color);
            padding: 1px 4px;
            border-radius: 3px;
        }

        /* Workspace main panel */
        .workspace {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100%;
            overflow: hidden;
        }

        .workspace-header {
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            background-color: var(--bg-card);
            flex-shrink: 0;
        }

        .header-title h2 {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-main);
            letter-spacing: -0.01em;
            text-transform: lowercase;
        }

        .header-title p {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 2px;
            text-transform: lowercase;
        }

        .tab-selectors {
            display: flex;
            gap: 6px;
        }

        .btn-ghost {
            background: transparent;
            border: 1px solid transparent;
            border-radius: var(--radius);
            cursor: pointer;
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 600;
            padding: 6px 12px;
            text-transform: lowercase;
            transition: all 0.1s ease;
        }

        .btn-ghost:hover {
            color: var(--text-main);
            background-color: var(--bg-muted);
        }

        .btn-ghost.active {
            color: var(--text-main);
            background-color: var(--bg-muted);
            border-color: var(--border-color);
        }

        /* Metrics statistic strip */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            background-color: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            flex-shrink: 0;
        }

        .stat-block {
            padding: 12px 24px;
            display: flex;
            flex-direction: column;
            gap: 2px;
            border-right: 1px solid var(--border-color);
        }

        .stat-block:last-child {
            border-right: none;
        }

        .stat-label {
            font-size: 10px;
            text-transform: lowercase;
            color: var(--text-muted);
            font-weight: 600;
            letter-spacing: 0.05em;
        }

        .stat-figure {
            font-size: 20px;
            font-weight: 700;
            color: var(--text-main);
        }

        /* Feeds Panel Layout */
        .feed-split {
            flex: 1;
            display: grid;
            grid-template-columns: 1.15fr 0.85fr;
            overflow: hidden;
        }

        .feed-pane {
            padding: 16px 24px;
            display: flex;
            flex-direction: column;
            height: 100%;
            overflow: hidden;
            background-color: var(--bg-card);
        }

        .feed-split > .feed-pane:first-child {
            border-right: 1px solid var(--border-color);
        }

        .feed-pane-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 12px;
        }

        .feed-pane-title {
            font-size: 12px;
            font-weight: 600;
            text-transform: lowercase;
            color: var(--text-main);
            letter-spacing: 0.05em;
        }

        .feed-content {
            flex: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }

        /* Log Table Entries */
        .log-row {
            display: flex;
            flex-direction: column;
            gap: 4px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
        }

        .log-meta-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 11px;
        }

        .status-dot {
            width: 5px;
            height: 5px;
            border-radius: 50%;
        }

        .dot-allow { background-color: var(--primary); }
        .dot-deny { background-color: var(--destructive); }
        .dot-info { background-color: var(--text-muted); }

        .log-type-tag {
            color: var(--text-muted);
            text-transform: lowercase;
            font-size: 9px;
            font-weight: 700;
            border: 1px solid var(--border-color);
            padding: 1px 5px;
            border-radius: 3px;
            letter-spacing: 0.05em;
        }

        .log-type-tag.localdns-tag {
            color: var(--info);
            border-color: var(--info);
            background-color: rgba(59, 130, 246, 0.06);
        }

        .log-server-id {
            color: var(--text-main);
            font-weight: 600;
        }

        .log-ip-badge {
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-muted);
        }

        .log-timestamp {
            color: var(--text-muted);
            margin-left: auto;
            font-family: var(--font-mono);
            font-size: 10px;
        }

        .log-desc {
            font-size: 12px;
            color: var(--text-main);
            line-height: 1.4;
        }

        .log-target-tag {
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--primary);
            background: var(--bg-muted);
            border: 1px solid var(--border-color);
            border-radius: 3px;
            padding: 2px 6px;
            display: inline-block;
            align-self: flex-start;
            margin-top: 4px;
        }

        .log-target-tag.localdns-target-tag {
            color: var(--info) !important;
            background: rgba(59, 130, 246, 0.03) !important;
            border-color: rgba(59, 130, 246, 0.15) !important;
        }

        /* gVisor Syscall Trace Console */
        .terminal-container {
            flex: 1;
            overflow-y: auto;
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-main);
            line-height: 1.5;
            background-color: var(--bg-base);
            border: 1px solid var(--border-color);
            padding: 12px;
            border-radius: var(--radius);
        }

        .terminal-row {
            margin-bottom: 6px;
            padding-bottom: 6px;
            border-bottom: 1px dashed var(--border-color);
        }

        .terminal-row-output {
            margin: 0;
            padding: 2px 0 2px 12px;
            border: none;
        }

        .term-prompt-char {
            color: var(--primary);
            margin-right: 4px;
        }

        .term-client-group {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-right: 6px;
        }

        .term-client-label {
            color: var(--primary);
            font-weight: 600;
            text-transform: lowercase;
        }

        .term-ip-badge {
            color: var(--text-muted);
            font-size: 9px;
        }

        .term-command-text {
            color: var(--text-main);
            word-break: break-all;
        }

        .term-timestamp-label {
            color: var(--text-muted);
            font-size: 9px;
            float: right;
            margin-top: 2px;
        }

        .no-data-placeholder {
            text-align: left;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: lowercase;
            padding: 10px 0;
            font-style: italic;
        }

        .filter-row {
            display: flex;
            gap: 4px;
        }

        .filter-lnk {
            font-size: 10px;
            color: var(--text-muted);
            text-decoration: none;
            cursor: pointer;
            text-transform: lowercase;
            font-weight: 600;
            padding: 3px 8px;
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            transition: all 0.1s ease;
        }

        .filter-lnk:hover, .filter-lnk.active {
            color: var(--text-main);
            border-color: var(--primary);
            background: var(--bg-muted);
        }

        /* Config layout */
        .config-layout {
            display: none;
            flex-direction: column;
            height: calc(100% - 60px);
            overflow-y: auto;
            background-color: var(--bg-base);
        }

        .config-section {
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
        }

        .config-section-title {
            font-size: 13px;
            font-weight: 600;
            text-transform: lowercase;
            color: var(--text-main);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 6px;
            margin-bottom: 4px;
            letter-spacing: 0.05em;
        }

        .input-field {
            display: flex;
            height: 2rem;
            width: 100%;
            border-radius: var(--radius);
            border: 1px solid var(--border-color);
            background-color: var(--bg-base);
            color: var(--text-main);
            padding: 0.3rem 0.6rem;
            font-size: 12px;
        }

        .input-field:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px var(--primary-glow);
        }

        .btn-primary {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--radius);
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            background-color: var(--primary);
            color: #ffffff;
            border: 1px solid transparent;
            height: 2rem;
            padding: 0 12px;
            user-select: none;
            transition: all 0.1s ease;
        }

        .btn-primary:hover {
            background-color: var(--primary-hover);
        }

        .btn-secondary {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--radius);
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid var(--border-color);
            background-color: var(--bg-muted);
            color: var(--text-main);
            height: 2rem;
            padding: 0 12px;
            user-select: none;
            transition: all 0.1s ease;
        }

        .btn-secondary:hover {
            background-color: var(--border-color);
        }

        /* Core diagnostics dashboard layout */
        .core-layout {
            display: none;
            flex-direction: column;
            height: calc(100% - 60px);
            overflow-y: auto;
            padding: 24px;
            gap: 20px;
        }

        .core-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        /* Auth Screen overlay */
        .auth-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: var(--bg-base);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        }

        .auth-card {
            border: 1px solid var(--border-color);
            background-color: var(--bg-card);
            padding: 24px;
            width: 380px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            border-radius: var(--radius);
        }

        .auth-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-main);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            text-transform: lowercase;
        }

        .auth-error {
            display: none;
            color: var(--destructive);
            font-size: 11px;
            font-family: var(--font-mono);
            border: 1px solid var(--destructive);
            background: rgba(239, 68, 68, 0.04);
            padding: 8px 12px;
            border-radius: var(--radius);
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .form-group label {
            font-size: 10px;
            font-weight: 600;
            text-transform: lowercase;
            color: var(--text-muted);
            letter-spacing: 0.05em;
        }

        /* Proof-of-work overlays */
        .pow-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background-color: rgba(0, 0, 0, 0.5);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        }

        .pow-card {
            border: 1px solid var(--border-color);
            background-color: var(--bg-card);
            border-radius: var(--radius);
            padding: 20px;
            width: 340px;
            text-align: center;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .pow-spinner {
            width: 20px;
            height: 20px;
            border: 2px solid var(--border-color);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .pow-title {
            font-size: 12px;
            font-weight: 600;
            text-transform: lowercase;
            color: var(--text-main);
        }

        .pow-desc {
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-muted);
        }

        ::-webkit-scrollbar {
            width: 5px;
            height: 5px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(0, 0, 0, 0.12);
            border-radius: 3px;
        }
        .dark ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.12);
        }
    </style>
</head>
<body>
    <div class="auth-overlay" id="authOverlay">
        <div class="auth-card">
            <h2 class="auth-title">ottergate // authorize</h2>
            <div class="auth-error" id="authError"></div>
            <div class="form-group">
                <label for="authApiKey">API Key Secret</label>
                <input type="password" class="input-field" id="authApiKey" placeholder="Enter session API Key...">
            </div>
            <div class="form-group">
                <label for="authDeviceId">Device Identifier</label>
                <input type="text" class="input-field" id="authDeviceId" placeholder="Enter workstation/device ID...">
            </div>
            <button class="btn-primary" onclick="submitAuth()">
                Establish Session
            </button>
        </div>
    </div>

    <div class="pow-overlay" id="powOverlay">
        <div class="pow-card">
            <div class="pow-spinner"></div>
            <h3 class="pow-title" id="powTitle">Solving Proof of Work Challenge</h3>
            <p class="pow-desc" id="powDesc">Finding numeric nonce for time-window hashing state...</p>
        </div>
    </div>

    <div class="app-frame">
        <aside class="sidebar" id="appSidebar">
            <div class="brand-section">
                <h1 class="brand-title">ottergate</h1>
                <p class="brand-desc">sandbox</p>
                <div class="theme-toggle-container">
                    <button class="theme-btn" onclick="toggleTheme()" title="Toggle Dark/Light Mode">
                        🌓 Toggle Dark Mode
                    </button>
                    <div class="color-dots-container" style="display: flex; gap: 8px; justify-content: center; margin-top: 8px;">
                        <span class="color-dot dot-blue" onclick="selectColor('blue')" title="blue theme" style="width: 14px; height: 14px; border-radius: 50%; background: #2563eb; cursor: pointer; border: 2px solid transparent; display: inline-block; box-sizing: border-box;"></span>
                        <span class="color-dot dot-emerald" onclick="selectColor('emerald')" title="emerald theme" style="width: 14px; height: 14px; border-radius: 50%; background: #059669; cursor: pointer; border: 2px solid transparent; display: inline-block; box-sizing: border-box;"></span>
                        <span class="color-dot dot-violet" onclick="selectColor('violet')" title="violet theme" style="width: 14px; height: 14px; border-radius: 50%; background: #7c3aed; cursor: pointer; border: 2px solid transparent; display: inline-block; box-sizing: border-box;"></span>
                        <span class="color-dot dot-orange" onclick="selectColor('orange')" title="orange theme" style="width: 14px; height: 14px; border-radius: 50%; background: #ea580c; cursor: pointer; border: 2px solid transparent; display: inline-block; box-sizing: border-box;"></span>
                    </div>
                </div>
            </div>
            <div class="index-menu" id="sandboxSidebarMenu">
                <span class="index-label">isolated sandboxes</span>
                <div class="index-list" id="clientList">
                    <div class="index-item active" id="clientAll" onclick="selectClient('all')">
                        <div class="index-header-row">
                            <span class="index-name">all clients</span>
                        </div>
                        <div class="index-ip-row">
                            <span class="index-ip">unified feed</span>
                            <span class="index-network-tag">gateway</span>
                        </div>
                    </div>
                </div>
            </div>
        </aside>

        <main class="workspace">
            <header class="workspace-header">
                <div class="header-title">
                    <h2>boundary security audit</h2>
                    <p>Kernel isolation monitoring and transparent DNS/Firewall proxy telemetry</p>
                </div>
                <div class="tab-selectors">
                    <button class="btn-ghost active" id="tabTelemetryBtn" onclick="switchTab('telemetry')">telemetry feed</button>
                    <button class="btn-ghost" id="tabConfigBtn" onclick="switchTab('config')">infra configuration</button>
                    <button class="btn-ghost" id="tabCoreBtn" onclick="switchTab('core')">control plane core</button>
                </div>
            </header>

            <section class="stats-grid" id="statsGrid">
                <div class="stat-block">
                    <span class="stat-label">Total Events</span>
                    <div class="stat-figure" id="metricTotal">0</div>
                </div>
                <div class="stat-block">
                    <span class="stat-label">Violations Dropped</span>
                    <div class="stat-figure" id="metricBlocked">0</div>
                </div>
                <div class="stat-block">
                    <span class="stat-label">DNS Queries Routed</span>
                    <div class="stat-figure" id="metricDns">0</div>
                </div>
                <div class="stat-block">
                    <span class="stat-label">Command Exec Traces</span>
                    <div class="stat-figure" id="metricExec">0</div>
                </div>
            </section>

            <div class="feed-split" id="telemetrySplit">
                <section class="feed-pane">
                    <header class="feed-pane-header">
                        <h3 class="feed-pane-title">Traffic & Violations</h3>
                        <div class="filter-row">
                            <span class="filter-lnk active" onclick="changeLogFilter('all', this)">all</span>
                            <span class="filter-lnk" onclick="changeLogFilter('dns', this)">dns</span>
                            <span class="filter-lnk" onclick="changeLogFilter('http', this)">http</span>
                            <span class="filter-lnk" onclick="changeLogFilter('firewall', this)">firewall</span>
                            <span class="filter-lnk" onclick="changeLogFilter('system', this)">system</span>
                        </div>
                    </header>
                    <div class="feed-content" id="logList">
                        <div class="no-data-placeholder">Awaiting secure network packets...</div>
                    </div>
                </section>

                <section class="feed-pane">
                    <header class="feed-pane-header">
                        <h3 class="feed-pane-title">gVisor Syscall Trace</h3>
                    </header>
                    <div class="terminal-container" id="terminalBody">
                        <div class="no-data-placeholder">Awaiting process traces from Sentry kernels...</div>
                    </div>
                </section>
            </div>

            <div class="config-layout" id="configLayout" style="padding: 24px; display: none;">
                <div class="config-section" style="flex: 1; display: flex; flex-direction: column; height: 100%;">
                    <h3 class="config-section-title">Infrastructure Configuration</h3>
                    <p style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px; text-transform: lowercase;">edit the active server configuration directly in raw JSON format. validation and component hot-reloads execute automatically.</p>
                    <textarea id="cfgRawJsonTextarea" style="font-family: var(--font-mono); font-size: 12px; flex: 1; min-height: 480px; resize: vertical; width: 100%; border: 1px solid var(--border-color); border-radius: var(--radius); padding: 16px; background: var(--bg-base); color: var(--text-main); line-height: 1.6;" spellcheck="false"></textarea>
                    
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
                        <div style="display: flex; gap: 12px;">
                            <button class="btn-primary" onclick="persistConfiguration()" style="text-transform: lowercase;">persist configuration</button>
                            <button class="btn-secondary" onclick="resetRawJsonConfig()" style="text-transform: lowercase;">reset / reload</button>
                        </div>
                        <span style="font-size: 11px; color: var(--text-muted); text-transform: lowercase; font-style: italic;">
                            note: committing reloads daemon components atomically via cryptographically checked PoW nonce.
                        </span>
                    </div>
                </div>
            </div>

            <div class="core-layout" id="coreLayout">
                <div class="core-grid">
                    <div class="config-section" style="grid-column: span 2;">
                        <h3 class="config-section-title">Operational Data Flow Pipeline</h3>
                        <div style="font-family: var(--font-mono); font-size: 11px; background: rgba(0,0,0,0.02); padding: 20px; border: 1px solid var(--border-color); line-height: 1.8; color: var(--primary); overflow-x: auto; border-radius: var(--radius);">
                            <pre style="margin: 0; white-space: pre;">
  [ Workstation Browser ] ───( X-Api-Key )───► [ Timing-Safe HMAC Guard ] ───( X-Pow-Nonce )───► [ Atomic Configuration Persistence ]
                                                      │                                                │
                                                      ▼                                                ▼
                                              [ API AUTH: OK ]                                 [ DAEMON LIVE RELOAD ]
                            </pre>
                        </div>
                    </div>

                    <div class="config-section">
                        <h3 class="config-section-title">System Core Parameters</h3>
                        <div style="font-family: var(--font-mono); font-size: 12px; line-height: 2.2; color: var(--text-main); opacity: 0.95;">
                            <div>├─ listen_port         :: <span id="corePort" style="color: var(--primary); font-weight: 500;">...</span></div>
                            <div>├─ unix_socket_path    :: <span id="coreSocketPath" style="color: var(--primary); font-weight: 500;">...</span></div>
                            <div>├─ persistent_storage  :: <span id="coreConfigFilePath" style="color: var(--primary); font-weight: 500; font-size: 11px;">...</span></div>
                            <div>├─ active_subscribers  :: <span id="coreSubscribersCount" style="color: var(--primary); font-weight: 500;">...</span> callback reloading daemons</div>
                            <div>└─ tls_channel_mode    :: <span id="coreTlsEnabled" style="color: var(--primary); font-weight: 500;">...</span></div>
                        </div>
                    </div>

                    <div class="config-section">
                        <h3 class="config-section-title">Active Cryptographic Keyring</h3>
                        <div style="font-family: var(--font-mono); font-size: 12px; line-height: 2.2; color: var(--text-main); opacity: 0.95;">
                            <div>├─ expected_api_hash   :: <span id="coreExpectedApiKeyHash" style="color: var(--primary); font-weight: 500; font-size: 11px;">...</span></div>
                            <div>├─ blind_index_salt    :: <span id="coreBlindIndexSalt" style="color: var(--primary); font-weight: 500; font-size: 11px;">...</span></div>
                            <div>├─ active_pow_epoch    :: Epoch Window #<span id="coreCurrentPoWWindow" style="color: var(--primary); font-weight: 500;">...</span></div>
                            <div>└─ challenge_nonces    :: <span id="coreSeenNoncesCount" style="color: var(--primary); font-weight: 500;">...</span> unique challenges processed</div>
                        </div>
                    </div>

                    <div class="config-section" style="grid-column: span 2;">
                        <h3 class="config-section-title">gVisor Secure Sandbox Isolation Status</h3>
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; font-family: var(--font-sans); font-size: 13px;">
                            <div style="padding: 16px; border: 1px solid var(--border-color); background: var(--bg-muted); border-radius: var(--radius); display: flex; flex-direction: column; gap: 6px;">
                                <span style="font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 6px;">🛡️ Sandbox Engine</span>
                                <span style="font-size: 11px; color: var(--text-muted);">runtime :: <strong style="color: var(--primary);">gVisor (runsc)</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">interception :: <strong style="color: var(--primary);">systrap (syscall trap)</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">security :: <strong style="color: #10b981;">sentry jailed kernel</strong></span>
                            </div>
                            <div style="padding: 16px; border: 1px solid var(--border-color); background: var(--bg-muted); border-radius: var(--radius); display: flex; flex-direction: column; gap: 6px;">
                                <span style="font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 6px;">🌐 Network Virtualization</span>
                                <span style="font-size: 11px; color: var(--text-muted);">network stack :: <strong style="color: var(--primary);">netstack (user-space Go)</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">isolation :: <strong style="color: var(--primary);">fully host-decoupled</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">proxy binding :: <strong style="color: #10b981;">transparent iptables redirect</strong></span>
                            </div>
                            <div style="padding: 16px; border: 1px solid var(--border-color); background: var(--bg-muted); border-radius: var(--radius); display: flex; flex-direction: column; gap: 6px;">
                                <span style="font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 6px;">📂 Secure Filesystem</span>
                                <span style="font-size: 11px; color: var(--text-muted);">file access protocol :: <strong style="color: var(--primary);">gofer (9p / client-server)</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">host path leakage :: <strong style="color: #10b981;">mitigated (no direct raw access)</strong></span>
                                <span style="font-size: 11px; color: var(--text-muted);">volume mounting :: <strong style="color: var(--primary);">chrooted namespaces</strong></span>
                            </div>
                        </div>
                        <div style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted); margin-top: 12px; border-top: 1px dashed var(--border-color); padding-top: 12px; display: flex; align-items: center; justify-content: space-between;">
                            <span>CPU Side-Channel Protections: <strong style="color: #10b981;">active (Spectre/Meltdown V4 sandboxed mitigations)</strong></span>
                            <span>Sentry emulation interface: <strong style="color: var(--primary);">emulated Linux ABI 5.15.0</strong></span>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let currentClient = 'all';
        let logFilter = 'all';
        let lastFilter = '';
        let allLogs = [];
        let discoveredClients = {};
        let activeTab = 'telemetry';
        let serverConfig = null;

        // Custom string hasher to generate deterministic DOM IDs
        function hashCode(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                hash = ((hash << 5) - hash) + str.charCodeAt(i);
                hash |= 0; 
            }
            return Math.abs(hash);
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function getAuthHeaders() {
            return {
                'X-Api-Key': localStorage.getItem('ottergate_api_key') || '',
                'X-Device-Id': localStorage.getItem('ottergate_device_id') || ''
            };
        }

        async function submitAuth() {
            const apiVal = document.getElementById('authApiKey').value.trim();
            const devVal = document.getElementById('authDeviceId').value.trim();
            const errorBox = document.getElementById('authError');

            if (!apiVal || !devVal) {
                errorBox.innerText = "AUTHENTICATION ERROR :: Missing credentials.";
                errorBox.style.display = "block";
                return;
            }

            localStorage.setItem('ottergate_api_key', apiVal);
            localStorage.setItem('ottergate_device_id', devVal);

            try {
                const resp = await fetch('/api/v1/containers', {
                    headers: { 'X-Api-Key': apiVal, 'X-Device-Id': devVal }
                });

                if (resp.ok) {
                    document.getElementById('authOverlay').style.display = 'none';
                    syncData();
                    setInterval(syncData, 2000);
                } else {
                    const errData = await resp.json().catch(() => ({}));
                    localStorage.removeItem('ottergate_api_key');
                    localStorage.removeItem('ottergate_device_id');
                    errorBox.innerText = "AUTHORIZATION DENIED :: " + (errData.error || "Invalid Secret Credentials");
                    errorBox.style.display = "block";
                }
            } catch (err) {
                localStorage.removeItem('ottergate_api_key');
                localStorage.removeItem('ottergate_device_id');
                errorBox.innerText = "NETWORKING EXCEPTION :: Failed to authenticate: " + err.message;
                errorBox.style.display = "block";
            }
        }

        function switchTab(tab) {
            activeTab = tab;
            const teleBtn = document.getElementById('tabTelemetryBtn');
            const confBtn = document.getElementById('tabConfigBtn');
            const coreBtn = document.getElementById('tabCoreBtn');

            teleBtn.classList.remove('active');
            confBtn.classList.remove('active');
            coreBtn.classList.remove('active');

            document.getElementById('statsGrid').style.display = 'none';
            document.getElementById('telemetrySplit').style.display = 'none';
            document.getElementById('configLayout').style.display = 'none';
            document.getElementById('coreLayout').style.display = 'none';

            const appSidebar = document.getElementById('appSidebar');
            if (appSidebar) {
                appSidebar.style.display = (tab === 'telemetry') ? 'flex' : 'none';
            }

            if (tab === 'telemetry') {
                teleBtn.classList.add('active');
                document.getElementById('statsGrid').style.display = 'grid';
                document.getElementById('telemetrySplit').style.display = 'grid';
            } else if (tab === 'config') {
                confBtn.classList.add('active');
                document.getElementById('configLayout').style.display = 'flex';
                renderConfigTab();
            } else if (tab === 'core') {
                coreBtn.classList.add('active');
                document.getElementById('coreLayout').style.display = 'flex';
                syncControlPlaneStatus();
            }
        }

        function selectClient(client) {
            currentClient = client;
            document.querySelectorAll('.index-item').forEach(c => c.classList.remove('active'));
            const card = document.getElementById(client === 'all' ? 'clientAll' : 'client_' + client);
            if (card) card.classList.add('active');
            
            containerClear();
            renderLogs();
            renderTerminal();
        }

        function containerClear() {
            document.getElementById('logList').innerHTML = '';
            document.getElementById('terminalBody').innerHTML = '';
            lastFilter = 'rebuilt';
        }

        function changeLogFilter(filter, btn) {
            logFilter = filter;
            document.querySelectorAll('.filter-lnk').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            renderLogs();
        }

        async function syncData() {
            if (document.getElementById('authOverlay').style.display !== 'none') {
                return;
            }

            try {
                const clientsResp = await fetch('/api/v1/containers', { headers: getAuthHeaders() });
                if (clientsResp.status === 401 || clientsResp.status === 403) {
                    document.getElementById('authOverlay').style.display = 'flex';
                    return;
                }

                if (clientsResp.ok) {
                    discoveredClients = await clientsResp.json();
                    updateClientsList();
                }

                const logsResp = await fetch('/api/v1/logs', { headers: getAuthHeaders() });
                if (logsResp.ok) {
                    allLogs = await logsResp.json();
                    updateMetrics();
                    renderLogs();
                    renderTerminal();
                }

                if (!serverConfig) {
                    const cfgResp = await fetch('/api/v1/config', { headers: getAuthHeaders() });
                    if (cfgResp.ok) {
                        serverConfig = await cfgResp.json();
                        if (activeTab === 'config') {
                            renderConfigTab();
                        }
                    }
                }

                if (activeTab === 'core') {
                    syncControlPlaneStatus();
                }
            } catch (err) {
                console.error("Subsystem synchronization failed:", err);
            }
        }

        function updateClientsList() {
            const list = document.getElementById('clientList');
            const activeIds = new Set();
            activeIds.add('clientAll');

            let counter = 1;
            Object.entries(discoveredClients).forEach(([ip, name]) => {
                const clientId = name;
                const cardId = 'client_' + clientId;
                activeIds.add(cardId);
                const prefixNum = String(counter++).padStart(2, '0');
                
                let card = document.getElementById(cardId);
                if (!card) {
                    card = document.createElement('div');
                    card.id = cardId;
                    card.onclick = () => selectClient(clientId);
                    list.appendChild(card);
                }
                
                card.className = 'index-item' + (currentClient === clientId ? ' active' : '');
                
                const escName = escapeHtml(name.toLowerCase());
                const escIp = escapeHtml(ip);
                const escPrefix = escapeHtml(prefixNum);
                
                const expectedHtml = 
                    '<div class="index-header-row">' +
                        '<span class="index-name"><span class="index-num">' + escPrefix + ' //</span> ' + escName + '</span>' +
                    '</div>' +
                    '<div class="index-ip-row">' +
                        '<span class="index-ip">' + escIp + '</span>' +
                        '<span class="index-network-tag">sandbox</span>' +
                    '</div>';
                
                if (card.innerHTML !== expectedHtml) {
                    card.innerHTML = expectedHtml;
                }
            });

            const items = list.querySelectorAll('.index-item');
            items.forEach(item => {
                if (item.id && !activeIds.has(item.id)) {
                    item.remove();
                }
            });
        }

        function updateMetrics() {
            document.getElementById('metricTotal').innerText = allLogs.length;
            document.getElementById('metricBlocked').innerText = allLogs.filter(l => l.status === 'deny').length;
            document.getElementById('metricDns').innerText = allLogs.filter(l => l.type === 'dns' || l.type === 'localdns').length;
            document.getElementById('metricExec').innerText = allLogs.filter(l => l.type === 'command').length;
        }

        function renderLogs() {
            const container = document.getElementById('logList');
            const filtered = allLogs.filter(l => {
                if (l.type === 'command') return false;
                if (l.type !== 'system') {
                    const resolvedName = discoveredClients[l.client_ip] || l.client_ip;
                    if (currentClient !== 'all' && resolvedName !== currentClient) return false;
                } else {
                    if (currentClient !== 'all') return false;
                }
                if (logFilter === 'all') return true;
                if (logFilter === 'firewall') {
                    return l.type === 'firewall' || l.status === 'deny';
                }
                return l.type === logFilter || (logFilter === 'dns' && l.type === 'localdns');
            });

            if (logFilter !== lastFilter) {
                container.innerHTML = '';
                lastFilter = logFilter;
            }

            if (filtered.length === 0) {
                if (!container.querySelector('.no-data-placeholder')) {
                    container.innerHTML = '<div class="no-data-placeholder">No matching events recorded.</div>';
                }
                return;
            }

            const placeholder = container.querySelector('.no-data-placeholder');
            if (placeholder) placeholder.remove();

            const activeIds = new Set();

            for (let i = filtered.length - 1; i >= 0; i--) {
                const log = filtered[i];
                const cleanTarget = (log.target || '').replace(/[^a-zA-Z0-9]/g, '');
                
                const logId = 'log_' + log.timestamp.replace(/[^a-zA-Z0-9]/g, '') + '_' + hashCode(log.details || '');
                activeIds.add(logId);

                if (!document.getElementById(logId)) {
                    const item = document.createElement('div');
                    item.className = 'log-row';
                    item.id = logId;

                    const timeStr = new Date(log.timestamp).toLocaleTimeString();
                    const dotClass = log.status === 'deny' ? 'dot-deny' : (log.status === 'allow' ? 'dot-allow' : 'dot-info');
                    const resolvedName = (discoveredClients[log.client_ip] || log.client_ip).toLowerCase();
                    const cleanIp = log.client_ip;

                    let clientGroupHtml = '';
                    if (log.type === 'system') {
                        clientGroupHtml = '<span class="log-server-id" style="color: var(--primary);">system</span><span class="log-ip-badge">[ gateway ]</span>';
                    } else {
                        clientGroupHtml = '<span class="log-server-id">' + escapeHtml(resolvedName) + '</span><span class="log-ip-badge">[ ' + escapeHtml(cleanIp) + ' ]</span>';
                    }

                    let typeClass = 'log-type-tag';
                    let typeLabel = log.type;
                    if (log.type === 'localdns') {
                        typeClass = 'log-type-tag localdns-tag';
                        typeLabel = 'local dns';
                    }

                    let html = 
                        '<div class="log-meta-bar">' +
                            '<span class="status-dot ' + dotClass + '"></span>' +
                            '<span class="' + typeClass + '">' + escapeHtml(typeLabel) + '</span>' +
                            clientGroupHtml +
                            '<span class="log-timestamp">' + escapeHtml(timeStr) + '</span>' +
                        '</div>' +
                        '<div class="log-desc">' + escapeHtml(log.details) + '</div>';

                    if (log.target) {
                        const targetClass = log.type === 'localdns' ? 'log-target-tag localdns-target-tag' : 'log-target-tag';
                        html += '<div class="' + targetClass + '">' + escapeHtml(log.target) + '</div>';
                    }
                    item.innerHTML = html;
                    container.insertBefore(item, container.firstChild);
                }
            }

            Array.from(container.children).forEach(child => {
                if (child.id && !activeIds.has(child.id)) {
                    child.remove();
                }
            });
        }

        function renderTerminal() {
            const term = document.getElementById('terminalBody');
            const cmdLogs = allLogs.filter(l => {
                if (l.type !== 'command') return false;
                const resolvedName = discoveredClients[l.client_ip] || l.client_ip;
                if (currentClient !== 'all' && resolvedName !== currentClient && l.client_ip !== currentClient) return false;
                return true;
            });

            if (cmdLogs.length === 0) {
                if (term.children.length === 0 || term.querySelector('.no-data-placeholder')) {
                    term.innerHTML = '<div class="no-data-placeholder">Awaiting process traces from Sentry kernels...</div>';
                }
                return;
            }

            const placeholder = term.querySelector('.no-data-placeholder');
            if (placeholder) placeholder.remove();

            const activeIds = new Set();

            for (let i = cmdLogs.length - 1; i >= 0; i--) {
                const log = cmdLogs[i];
                const cmdId = 'cmd_' + log.timestamp.replace(/[^a-zA-Z0-9]/g, '') + '_' + hashCode(log.details || '');
                activeIds.add(cmdId);

                if (!document.getElementById(cmdId)) {
                    const line = document.createElement('div');
                    line.id = cmdId;

                    const timeStr = new Date(log.timestamp).toLocaleTimeString();
                    const resolvedName = (discoveredClients[log.client_ip] || log.client_ip).toLowerCase();
                    const cleanIp = log.client_ip;
                    
                    if (log.target === 'output') {
                        line.className = 'terminal-row-output';
                        line.innerHTML = '<div class="term-command-text" style="color: var(--text-muted); font-family: var(--font-mono); white-space: pre-wrap;">' + escapeHtml(log.details) + '</div>';
                    } else {
                        line.className = 'terminal-row';
                        line.innerHTML = 
                            '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; margin-top: 8px;">' +
                                '<span>' +
                                    '<span class="term-prompt-char">#</span>' +
                                    '<span class="term-client-label">' + escapeHtml(resolvedName) + '</span> ' +
                                    '<span class="term-ip-badge">[ ' + escapeHtml(cleanIp) + ' ]</span>' +
                                '</span>' +
                                '<span class="term-timestamp-label">' + escapeHtml(timeStr) + '</span>' +
                            '</div>' +
                            '<div class="term-command-text" style="padding-left: 12px; color: var(--text-main);">' + escapeHtml(log.details) + '</div>';
                    }
                    
                    term.insertBefore(line, term.firstChild);
                }
            }

            Array.from(term.children).forEach(child => {
                if (child.id && !activeIds.has(child.id)) {
                    child.remove();
                }
            });
        }

        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('ottergate_theme', isDark ? 'dark' : 'light');
        }

        function selectColor(color) {
            document.documentElement.setAttribute('data-color', color);
            localStorage.setItem('ottergate_color', color);
            
            document.querySelectorAll('.color-dot').forEach(dot => {
                dot.classList.remove('active');
                if (dot.classList.contains('dot-' + color)) {
                    dot.classList.add('active');
                }
            });
        }

        const savedTheme = localStorage.getItem('ottergate_theme') || 'dark';
        if (savedTheme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }

        const savedColor = localStorage.getItem('ottergate_color') || 'blue';
        selectColor(savedColor);

        async function renderConfigTab() {
            if (!serverConfig) {
                const cfgResp = await fetch('/api/v1/config', { headers: getAuthHeaders() });
                if (cfgResp.ok) {
                    serverConfig = await cfgResp.json();
                } else {
                    return;
                }
            }
            document.getElementById('cfgRawJsonTextarea').value = JSON.stringify(serverConfig, null, 4);
        }

        async function resetRawJsonConfig() {
            serverConfig = null;
            renderConfigTab();
        }

        function sha256_pure(ascii) {
            function rightRotate(value, amount) {
                return (value >>> amount) | (value << (32 - amount));
            }
            const mathPow = Math.pow;
            const maxWord = mathPow(2, 32);
            let result = '';
            const words = [];
            const asciiLength = ascii.length * 8;
            
            const hash = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ];
            
            const k = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            ];

            let sascii = ascii + '\x80';
            while (sascii.length % 64 !== 56) sascii += '\x00';
            
            for (let i = 0; i < sascii.length; i++) {
                words[i >> 2] |= sascii.charCodeAt(i) << (24 - (i % 4) * 8);
            }
            words[words.length] = ((asciiLength / maxWord) | 0);
            words[words.length] = (asciiLength | 0);
            
            for (let j = 0; j < words.length; j += 16) {
                const w = words.slice(j, j + 16);
                const h_temp = hash.slice(0);
                
                for (let i = 0; i < 64; i++) {
                    if (i >= 16) {
                        const w15 = w[i - 15];
                        const w2 = w[i - 2];
                        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
                        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
                        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
                    }
                    
                    const a = h_temp[0], b = h_temp[1], c = h_temp[2], d = h_temp[3];
                    const e = h_temp[4], f = h_temp[5], g = h_temp[6], h_val = h_temp[7];
                    
                    const s0_h = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                    const maj = (a & b) ^ (a & c) ^ (b & c);
                    const t2 = (s0_h + maj) | 0;
                    const s1_h = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                    const ch = (e & f) ^ ((~e) & g);
                    const t1 = (h_val + s1_h + ch + k[i] + (w[i] || 0)) | 0;
                    
                    h_temp.unshift((t1 + t2) | 0);
                    h_temp[4] = (h_temp[4] + t1) | 0;
                    h_temp.pop();
                }
                
                for (let i = 0; i < 8; i++) {
                    hash[i] = (hash[i] + h_temp[i]) | 0;
                }
            }
            
            for (let i = 0; i < 8; i++) {
                let val = hash[i];
                if (val < 0) val += maxWord;
                result += val.toString(16).padStart(8, '0');
            }
            return result;
        }

        async function computeSHA256(message) {
            if (window.crypto && window.crypto.subtle) {
                try {
                    const msgBuffer = new TextEncoder().encode(message);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                } catch (e) {
                    console.warn("Subtle crypto error, falling back to pure JS SHA-256:", e);
                }
            }
            return sha256_pure(message);
        }

        async function persistConfiguration() {
            const overlay = document.getElementById('powOverlay');
            overlay.style.display = 'flex';

            try {
                const payloadStr = document.getElementById('cfgRawJsonTextarea').value;
                let parsed;
                try {
                    parsed = JSON.parse(payloadStr);
                } catch (err) {
                    alert("JSON SYNTAX ERROR :: " + err.message);
                    return;
                }

                const payloadHash = await computeSHA256(payloadStr);

                const challengeResp = await fetch('/api/v1/pow-challenge?payload_hash=' + payloadHash, {
                    headers: getAuthHeaders()
                });

                if (!challengeResp.ok) {
                    throw new Error("Failed to fetch Proof of Work challenge: " + challengeResp.statusText);
                }

                const chalData = await challengeResp.json();
                const challenge = chalData.challenge;

                let nonce = 0;
                let found = false;
                
                while (!found) {
                    const testString = challenge + nonce;
                    const hashResult = await computeSHA256(testString);
                    if (hashResult.substring(0, 4) === '0000') {
                        found = true;
                        break;
                    }
                    nonce++;
                }

                const putHeaders = Object.assign({}, getAuthHeaders(), {
                    'Content-Type': 'application/json',
                    'X-Pow-Nonce': String(nonce)
                });

                const putResp = await fetch('/api/v1/config', {
                    method: 'PUT',
                    headers: putHeaders,
                    body: payloadStr
                });

                if (putResp.ok) {
                    serverConfig = parsed;
                    alert("Configuration persisted and components reloaded successfully!");
                    renderConfigTab();
                } else {
                    const errData = await putResp.json().catch(() => ({}));
                    alert("PERSISTENCE FAULT :: " + (errData.error || "Cryptographic constraint rejection."));
                }
            } catch (err) {
                console.error(err);
                alert("DEPLOYMENT ERROR :: " + err.message);
            } finally {
                overlay.style.display = 'none';
            }
        }

        async function syncControlPlaneStatus() {
            try {
                const resp = await fetch('/api/v1/controlplane-status', { headers: getAuthHeaders() });
                if (resp.ok) {
                    const status = await resp.json();
                    document.getElementById('corePort').innerText = status.port;
                    document.getElementById('coreSocketPath').innerText = status.socketPath || 'None';
                    document.getElementById('coreConfigFilePath').innerText = status.configFilePath;
                    document.getElementById('coreSubscribersCount').innerText = status.subscribersCount;
                    document.getElementById('coreTlsEnabled').innerText = status.tlsEnabled ? 'SECURE TLS DUAL CHANNEL' : 'PLAINTEXT INTERCEPT';
                    document.getElementById('coreExpectedApiKeyHash').innerText = status.expectedApiKeyHash;
                    document.getElementById('coreBlindIndexSalt').innerText = status.blindIndexSalt;
                    document.getElementById('coreCurrentPoWWindow').innerText = status.currentPoWWindow;
                    document.getElementById('coreSeenNoncesCount').innerText = status.seenNoncesCount;
                }
            } catch (err) {
                console.error("Failed to sync control plane core status:", err);
            }
        }

        const savedApi = localStorage.getItem('ottergate_api_key');
        const savedDev = localStorage.getItem('ottergate_device_id');

        if (savedApi && savedDev) {
            document.getElementById('authOverlay').style.display = 'none';
            syncData();
            setInterval(syncData, 2000);
        }
    </script>
</body>
</html>`