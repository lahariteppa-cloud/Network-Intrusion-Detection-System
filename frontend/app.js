/**
 * NIDS - Network Intrusion Detection System
 * Interactivity, Charts, Simulation, and Flow Logic
 */

// =========================================================
// 0. Theme Manager (Dark / Light Theme)
// =========================================================
const ThemeManager = {
    STORAGE_KEY: 'nids_theme',
    
    getStoredTheme() {
        return localStorage.getItem(this.STORAGE_KEY);
    },

    getSystemTheme() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    },

    getCurrentTheme() {
        return this.getStoredTheme() || this.getSystemTheme();
    },

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        if (theme === 'dark') {
            document.documentElement.classList.add('dark-theme');
        } else {
            document.documentElement.classList.remove('dark-theme');
        }
        localStorage.setItem(this.STORAGE_KEY, theme);
        this.updateToggleButtons(theme);

        // Dispatch a custom event in case charts or other widgets need updating
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
    },

    updateToggleButtons(theme) {
        const toggleButtons = document.querySelectorAll('.theme-toggle-btn, #themeToggleBtn');
        toggleButtons.forEach(btn => {
            const isDark = theme === 'dark';
            const icon = btn.querySelector('i');
            const label = btn.querySelector('.theme-toggle-label');

            if (icon) {
                icon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
            }
            if (label) {
                label.textContent = isDark ? 'Light' : 'Dark';
            }
            btn.setAttribute('aria-label', `Switch to ${isDark ? 'Light' : 'Dark'} Mode`);
            btn.setAttribute('title', `Switch to ${isDark ? 'Light' : 'Dark'} Mode`);
        });
    },

    toggleTheme() {
        const nextTheme = this.getCurrentTheme() === 'dark' ? 'light' : 'dark';
        this.applyTheme(nextTheme);
        showToast(`Switched to ${nextTheme === 'dark' ? 'Dark' : 'Light'} Mode`, 'info');
    },

    init() {
        // Apply immediately
        this.applyTheme(this.getCurrentTheme());

        // Listen for OS scheme changes
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (!this.getStoredTheme()) {
                this.applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
};

// Immediately apply theme before DOMContentLoaded to prevent any white flash
ThemeManager.init();

document.addEventListener('DOMContentLoaded', () => {
    initThemeToggle();
    initCharts();
    initAlertFilters();
    initSearchFilter();
    initReportModal();
    initAuthForms();
    initActionButtons();
    loadDashboardData();
    loadDashboardAlerts();
    loadAlertsPage();
    loadReportsPage();
});

function initThemeToggle() {
    const toggleButtons = document.querySelectorAll('.theme-toggle-btn, #themeToggleBtn');
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            ThemeManager.toggleTheme();
        });
    });
    // Ensure initial button icons match current theme
    ThemeManager.updateToggleButtons(ThemeManager.getCurrentTheme());
}

// =========================================================
// Toast notification helper
// =========================================================
function showToast(message, type = 'info') {
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(toastContainer);
    }

    const toast = document.createElement('div');
    const isDark = ThemeManager.getCurrentTheme() === 'dark';
    const bgColors = {
        success: '#10b981',
        error: '#ef4444',
        info: '#3b82f6',
        warning: '#f59e0b'
    };

    toast.style.cssText = `
        background: ${isDark ? '#1e293b' : '#ffffff'};
        color: ${isDark ? '#f8fafc' : '#0f172a'};
        padding: 14px 20px;
        border-radius: 12px;
        border-left: 5px solid ${bgColors[type] || '#3b82f6'};
        box-shadow: 0 10px 25px -3px rgba(0,0,0,${isDark ? '0.5' : '0.1'}), 0 4px 6px -2px rgba(0,0,0,0.05);
        font-size: 14px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 12px;
        animation: toastSlideIn 0.3s ease-out;
        min-width: 260px;
        border-top: 1px solid ${isDark ? '#334155' : '#e2e8f0'};
        border-right: 1px solid ${isDark ? '#334155' : '#e2e8f0'};
        border-bottom: 1px solid ${isDark ? '#334155' : '#e2e8f0'};
    `;

    const iconClass = type === 'success' ? 'fa-circle-check text-green' :
                      type === 'error' ? 'fa-triangle-exclamation text-red' :
                      type === 'warning' ? 'fa-bell text-amber' : 'fa-info-circle text-blue';

    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${message}</span>`;
    toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// =========================================================
// 1. Interactive Charts for Dashboard
// =========================================================
function initCharts() {
    const trafficCanvas = document.getElementById('trafficChart');
    if (trafficCanvas) {
        drawTrafficChart(trafficCanvas);
        window.addEventListener('resize', () => drawTrafficChart(trafficCanvas));
        window.addEventListener('themeChanged', () => drawTrafficChart(trafficCanvas));
    }

    const attackCanvas = document.getElementById('attackChart');
    if (attackCanvas) {
        drawAttackChart(attackCanvas);
        window.addEventListener('resize', () => drawAttackChart(attackCanvas));
        window.addEventListener('themeChanged', () => drawAttackChart(attackCanvas));
    }
}

function drawTrafficChart(canvas) {
    const ctx = canvas.getContext('2d');
    const width = canvas.parentElement.clientWidth || 400;
    const height = 220;
    canvas.width = width;
    canvas.height = height;

    const isDark = ThemeManager.getCurrentTheme() === 'dark';
    const dataPoints = [45, 60, 52, 78, 95, 80, 110, 135, 120, 145, 130, 160];
    const labels = ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'];
    
    ctx.clearRect(0, 0, width, height);

    // Draw grid lines
    ctx.strokeStyle = isDark ? '#1e293b' : '#f1f5f9';
    ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
        const y = (height - 40) * (i / 4);
        ctx.beginPath();
        ctx.moveTo(30, y);
        ctx.lineTo(width - 20, y);
        ctx.stroke();
    }

    // Draw Area Gradient
    const stepX = (width - 60) / (dataPoints.length - 1);
    const maxVal = 180;

    const gradient = ctx.createLinearGradient(0, 0, 0, height - 30);
    gradient.addColorStop(0, isDark ? 'rgba(59, 130, 246, 0.35)' : 'rgba(37, 99, 235, 0.25)');
    gradient.addColorStop(1, isDark ? 'rgba(59, 130, 246, 0.01)' : 'rgba(37, 99, 235, 0.01)');

    ctx.beginPath();
    ctx.moveTo(40, height - 30);
    dataPoints.forEach((val, index) => {
        const x = 40 + index * stepX;
        const y = height - 30 - (val / maxVal) * (height - 60);
        if (index === 0) ctx.lineTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.lineTo(40 + (dataPoints.length - 1) * stepX, height - 30);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw Line
    ctx.beginPath();
    ctx.strokeStyle = isDark ? '#60a5fa' : '#2563eb';
    ctx.lineWidth = 3;
    ctx.lineJoin = 'round';
    dataPoints.forEach((val, index) => {
        const x = 40 + index * stepX;
        const y = height - 30 - (val / maxVal) * (height - 60);
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Draw Points & Labels
    dataPoints.forEach((val, index) => {
        const x = 40 + index * stepX;
        const y = height - 30 - (val / maxVal) * (height - 60);

        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = isDark ? '#111827' : '#ffffff';
        ctx.fill();
        ctx.strokeStyle = isDark ? '#60a5fa' : '#2563eb';
        ctx.lineWidth = 2;
        ctx.stroke();

        // X Labels (show every alternate)
        if (index % 2 === 0) {
            ctx.fillStyle = isDark ? '#94a3b8' : '#64748b';
            ctx.font = '11px Plus Jakarta Sans';
            ctx.textAlign = 'center';
            ctx.fillText(labels[index], x, height - 10);
        }
    });
}

function drawAttackChart(canvas) {
    const ctx = canvas.getContext('2d');
    const width = canvas.parentElement.clientWidth || 400;
    const height = 220;
    canvas.width = width;
    canvas.height = height;

    const isDark = ThemeManager.getCurrentTheme() === 'dark';
    const attacks = [
        { label: 'DDoS', value: 45, color: '#ef4444' },
        { label: 'SQL Injection', value: 25, color: '#f59e0b' },
        { label: 'Brute Force', value: 18, color: '#10b981' },
        { label: 'Port Scan', value: 12, color: '#3b82f6' }
    ];

    ctx.clearRect(0, 0, width, height);

    const centerX = width / 3;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    const innerRadius = radius * 0.6;

    let startAngle = -Math.PI / 2;
    const total = attacks.reduce((sum, item) => sum + item.value, 0);

    attacks.forEach(item => {
        const sliceAngle = (item.value / total) * 2 * Math.PI;

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = item.color;
        ctx.fill();

        startAngle += sliceAngle;
    });

    // Legend on the right side
    const legendX = width * 0.65;
    let legendY = 40;

    attacks.forEach(item => {
        // Color dot
        ctx.beginPath();
        ctx.arc(legendX, legendY + 5, 6, 0, Math.PI * 2);
        ctx.fillStyle = item.color;
        ctx.fill();

        // Text
        ctx.fillStyle = isDark ? '#f8fafc' : '#0f172a';
        ctx.font = 'bold 13px Plus Jakarta Sans';
        ctx.textAlign = 'left';
        ctx.fillText(item.label, legendX + 16, legendY + 9);

        // Percentage
        ctx.fillStyle = isDark ? '#94a3b8' : '#64748b';
        ctx.font = '12px Plus Jakarta Sans';
        ctx.fillText(`${item.value}%`, legendX + 120, legendY + 9);

        legendY += 34;
    });
}

// =========================================================
// 2. Alert Severity Filtering
// =========================================================
function initAlertFilters() {
    const filterPills = document.querySelectorAll('.filter-pill');

    if (!filterPills.length) return;

    filterPills.forEach(pill => {
        pill.addEventListener('click', () => {

            // Remove active state from all buttons
            filterPills.forEach(p => p.classList.remove('active'));

            // Activate clicked button
            pill.classList.add('active');

            // Get selected filter
            const filter = pill.getAttribute('data-filter');

            // IMPORTANT:
            // Get alert cards AFTER they have been loaded by the API
            const alertItems = document.querySelectorAll('.alert-card-item');

            alertItems.forEach(item => {
                if (
                    filter === 'all' ||
                    item.classList.contains(filter)
                ) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
}

// =========================================================
// 3. Search filter for tables and lists
// =========================================================
function initSearchFilter() {
    const searchInputs = document.querySelectorAll('.table-search-input');
    searchInputs.forEach(input => {
        input.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const targetTable = document.querySelector(e.target.getAttribute('data-target-table') || 'table');
            if (targetTable) {
                const rows = targetTable.querySelectorAll('tbody tr, tr:not(:first-child)');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            }
        });
    });
}

// =========================================================
// 4. Report details modal
// =========================================================
const reportDetails = {
    'R001': { title: 'Daily Traffic & Threat Summary', date: '04-08-2026', totalPackets: '1,245,890', threats: '3 DDoS, 1 SQLi', status: 'Completed', analyst: 'Auto-AI Sensor 4' },
    'R002': { title: 'Weekly Vulnerability Assessment', date: '04-08-2026', totalPackets: '8,932,100', threats: '14 Brute Force, 5 Port Scans', status: 'Completed', analyst: 'SecOps Team' },
    'R003': { title: 'Monthly Anomaly Detection Audit', date: '04-08-2026', totalPackets: '34,120,400', threats: '27 Blocked Invasions', status: 'Pending Review', analyst: 'Pending' },
    'R004': { title: 'High-Severity Attack Postmortem', date: '04-08-2026', totalPackets: '450,200', threats: 'Zero-Day Probe', status: 'Completed', analyst: 'Incident Response' }
};

function initReportModal() {
    const modalBackdrop = document.getElementById('reportModal');
    const closeBtn = document.getElementById('modalCloseBtn');

    if (closeBtn && modalBackdrop) {
        closeBtn.addEventListener('click', () => {
            modalBackdrop.classList.remove('active');
        });

        modalBackdrop.addEventListener('click', (e) => {
            if (e.target === modalBackdrop) {
                modalBackdrop.classList.remove('active');
            }
        });
    }

    document.querySelectorAll('.view-report-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const reportId = e.target.getAttribute('data-id') || 'R001';
            const data = reportDetails[reportId] || reportDetails['R001'];

            if (modalBackdrop) {
                document.getElementById('modalReportId').innerText = reportId;
                document.getElementById('modalReportTitle').innerText = data.title;
                document.getElementById('modalReportDate').innerText = data.date;
                document.getElementById('modalReportPackets').innerText = data.totalPackets;
                document.getElementById('modalReportThreats').innerText = data.threats;
                document.getElementById('modalReportStatus').innerText = data.status;
                document.getElementById('modalReportAnalyst').innerText = data.analyst;
                modalBackdrop.classList.add('active');
            } else {
                alert(`Report ${reportId}: ${data.title}\nDate: ${data.date}\nThreats: ${data.threats}\nStatus: ${data.status}`);
            }
        });
    });
}

// =========================================================
// 5. Auth logic with feedback
// =========================================================
function initAuthForms() {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const usernameInput = loginForm.querySelector('input[type="text"]');
            const username = usernameInput ? usernameInput.value.trim() : 'User';
            
            showToast(`Logging in as ${username || 'Admin'}...`, 'info');
            setTimeout(() => {
                showToast('Authentication Successful!', 'success');
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 800);
            }, 600);
        });
    }

    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            showToast('Account created successfully!', 'success');
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 1000);
        });
    }

    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const emailInput = forgotPasswordForm.querySelector('input[type="email"]');
            const email = emailInput ? emailInput.value.trim() : '';
            
            showToast(`Sending reset link to ${email || 'your email'}...`, 'info');
            setTimeout(() => {
                showToast('Password reset link sent! Check your email.', 'success');
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 800);
            }, 600);
        });
    }
}

// =========================================================
// 6. Action buttons (Simulation, Download, Clear)
// =========================================================
function initActionButtons() {
    const simulateBtn = document.getElementById('simulateAttackBtn');
    if (simulateBtn) {
        simulateBtn.addEventListener('click', () => {
            simulateBtn.disabled = true;
            simulateBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Simulating...';
            showToast('Simulating network probe...', 'warning');

            setTimeout(() => {
                simulateBtn.disabled = false;
                simulateBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Simulate Attack';
                
                // Increment detected count
                const threatCountEl = document.getElementById('statThreatsCount');
                if (threatCountEl) {
                    let current = parseInt(threatCountEl.innerText) || 27;
                    threatCountEl.innerText = current + 1;
                }

                showToast('AI Model detected and mitigated Port Scan from 198.51.100.44!', 'error');
            }, 1200);
        });
    }

    const exportBtn = document.getElementById('exportReportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            showToast('Generating security audit report...', 'info');
            setTimeout(() => {
                const csvContent = "data:text/csv;charset=utf-8,Time,Attack_Type,Source_IP,Status\n10:20 AM,DDoS Attack,192.168.1.10,Blocked\n10:45 AM,SQL Injection,172.16.0.25,Detected\n11:10 AM,Brute Force,10.0.0.15,Blocked\n11:35 AM,Port Scan,192.168.0.55,Monitoring";
                const encodedUri = encodeURI(csvContent);
                const link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", `NIDS_Security_Log_${new Date().toISOString().slice(0,10)}.csv`);
                document.body.appendChild(link);
                link.click();
                link.remove();
                showToast('Report CSV downloaded successfully!', 'success');
            }, 800);
        });
    }
    const downloadModalBtn = document.getElementById('downloadModalReportBtn');

if (downloadModalBtn) {
    downloadModalBtn.addEventListener('click', () => {

        const modal = document.getElementById('reportModal');
        const reportId = modal?.dataset.reportId;

        if (!reportId) {
            showToast('Report ID not found', 'error');
            return;
        }

        showToast('Downloading report...', 'info');

        const downloadUrl =
            `http://127.0.0.1:5000/api/reports/${reportId}/download`;

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = '';
        document.body.appendChild(link);
        link.click();
        link.remove();

        showToast('Report PDF download started!', 'success');
    });
}

    const clearAlertsBtn = document.getElementById('clearAlertsBtn');
    if (clearAlertsBtn) {
        clearAlertsBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to acknowledge and archive all current alerts?')) {
                const feed = document.querySelector('.alert-feed');
                if (feed) {
                    feed.innerHTML = `
                        <div style="text-align: center; padding: 40px; background: var(--bg-card); border: 1px dashed var(--border-color); border-radius: 16px; color: var(--text-muted);">
                            <i class="fa-solid fa-circle-check" style="font-size: 36px; color: #10b981; margin-bottom: 12px; display: block;"></i>
                            <h3 style="color: var(--text-primary); margin-bottom: 6px;">All Alerts Acknowledged</h3>
                            <p>No active threats pending resolution in the queue.</p>
                        </div>
                    `;
                }
                showToast('All alerts cleared and logged into history.', 'success');
            }
        });
    }
}
async function loadDashboardData() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/dashboard');

        if (!response.ok) {
            throw new Error('Failed to fetch dashboard data');
        }

        const data = await response.json();

        if (data.success) {
            document.getElementById('statTraffic').innerText =
                data.total_traffic;

            document.getElementById('statThreatsCount').innerText =
                data.threats_detected;

            document.getElementById('statAccuracy').innerText =
                data.detection_accuracy + '%';

            document.getElementById('statBlockedIPs').innerText =
                data.blocked_ips;
        }

    } catch (error) {
        console.error('Dashboard API Error:', error);
    }
}
async function loadDashboardAlerts() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/alerts');

        if (!response.ok) {
            throw new Error('Failed to fetch alerts');
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error('Failed to load alerts');
        }

        const tableBody = document.querySelector('#dashboardAlertsTable tbody');

        if (!tableBody) return;

        tableBody.innerHTML = '';

        data.alerts.forEach(alert => {
            let riskClass = 'medium';

            if (alert.status === 'Blocked') {
                riskClass = 'high';
            } else if (alert.status === 'Monitoring') {
                riskClass = 'low';
            }

            let actionClass = 'info';

            if (alert.status === 'Blocked') {
                actionClass = 'success';
            }

            tableBody.innerHTML += `
                <tr>
                    <td><strong>${alert.time}</strong></td>
                    <td>${alert.attack_type}</td>
                    <td><code>${alert.ip_address}</code></td>
                    <td>
                        <span class="badge ${riskClass}">
                            ${riskClass.charAt(0).toUpperCase() + riskClass.slice(1)} Risk
                        </span>
                    </td>
                    <td>
                        <span class="badge ${actionClass}">
                            ${alert.status}
                        </span>
                    </td>
                </tr>
            `;
        });

    } catch (error) {
        console.error('Dashboard Alerts Error:', error);
    }
}
async function loadAlertsPage() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/alerts');

        if (!response.ok) {
            throw new Error('Failed to fetch alerts');
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error('Failed to load alerts');
        }

        // Update statistics
        document.getElementById('totalAlerts').innerText = data.total_alerts;
        document.getElementById('highRiskAlerts').innerText = data.high_risk;
        document.getElementById('mediumRiskAlerts').innerText = data.medium_risk;
        document.getElementById('lowRiskAlerts').innerText = data.low_risk;

        // Update filter counts
        document.getElementById('filterAll').innerText =
            `All Alerts (${data.total_alerts})`;

        document.getElementById('filterHigh').innerText =
            `High Risk (${data.high_risk})`;

        document.getElementById('filterMedium').innerText =
            `Medium Risk (${data.medium_risk})`;

        document.getElementById('filterLow').innerText =
            `Low Risk (${data.low_risk})`;

        // Update alert cards
        const alertFeed = document.getElementById('alertFeed');

        if (!alertFeed) return;

        alertFeed.innerHTML = '';

        data.alerts.forEach(alert => {

            let riskClass =  alert.severity || 'medium';
            let icon = 'fa-triangle-exclamation';
            let iconClass = 'text-amber';

            if (riskClass === 'high') {
                icon = 'fa-circle-radiation';
                iconClass = 'text-red';
            } else if (riskClass === 'low') {
                icon = 'fa-radar';
                iconClass = 'text-green';
            } else if (riskClass === 'info') {
                icon = 'fa-circle-info';
                iconClass = 'text-blue';
            }

            alertFeed.innerHTML += `
                <div class="alert-card-item ${riskClass}">
                    <div class="alert-main-content">
                        <h3>
                            <i class="fa-solid ${icon} ${iconClass}"></i>
                            ${alert.attack_type}
                        </h3>

                        <div class="alert-meta">
                            <span>
                                <strong>Source IP:</strong>
                                <code>${alert.ip_address}</code>
                            </span>

                            <span>
                                <strong>Time:</strong>
                                ${alert.time}
                            </span>

                            <span>
                                <strong>Status:</strong>
                                ${alert.status}
                            </span>
                        </div>
                    </div>

                    <span class="badge ${riskClass}">
                        ${alert.status}
                    </span>
                </div>
            `;
        });

    } catch (error) {
        console.error('Alerts API Error:', error);
    }
}function initReportViewButtons() {
    const buttons = document.querySelectorAll('.view-report-btn');

    buttons.forEach(button => {

        // Prevent duplicate event listeners
        button.onclick = async function () {

            const reportId = this.getAttribute('data-id');

            console.log('View button clicked. Report ID:', reportId);

            if (!reportId) {
                console.error('No report ID found');
                return;
            }

            const modal = document.getElementById('reportModal');

            if (!modal) {
                console.error('reportModal not found');
                return;
            }

            // Show modal immediately
            modal.classList.add('active');

            // Show loading state
            document.getElementById('modalReportId').innerText =
                'R' + String(reportId).padStart(3, '0');

            document.getElementById('modalReportTitle').innerText =
                'Loading...';

            document.getElementById('modalReportType').innerText =
                'Loading...';

            document.getElementById('modalReportDate').innerText =
                'Loading...';

            document.getElementById('modalReportStatus').innerText =
                'Loading...';

            document.getElementById('modalReportSummary').innerText =
                'Loading...';

            try {

                const response = await fetch(
                    `http://127.0.0.1:5000/api/reports/${reportId}`
                );

                console.log(
                    'Report API status:',
                    response.status
                );

                if (!response.ok) {
                    throw new Error(
                        `HTTP ${response.status}`
                    );
                }

                const result = await response.json();

                console.log(
                    'Report API response:',
                    result
                );

                if (!result.success || !result.data) {
                    throw new Error(
                        result.message || 'Report not found'
                    );
                }

                const report = result.data;

                // Report ID
                document.getElementById('modalReportId').innerText =
                    'R' + String(report.id).padStart(3, '0');

                // Title
                document.getElementById('modalReportTitle').innerText =
                    report.name || 'N/A';

                // Type
                document.getElementById('modalReportType').innerText =
                    report.type || 'N/A';

                // Date
                if (report.generated_at) {
                    const date = new Date(report.generated_at);

                    document.getElementById('modalReportDate').innerText =
                        isNaN(date.getTime())
                            ? report.generated_at
                            : date.toLocaleString();
                } else {
                    document.getElementById('modalReportDate').innerText =
                        'N/A';
                }

                // Status
                document.getElementById('modalReportStatus').innerText =
                    report.status || 'N/A';

                // Summary
                document.getElementById('modalReportSummary').innerText =
                    report.summary || 'No summary available';

                // Store report information in modal
                modal.dataset.reportId = report.id;
                modal.dataset.filePath = report.file_path || '';

                console.log(
                    'Report loaded successfully:',
                    report
                );

            } catch (error) {

                console.error(
                    'Report Detail API Error:',
                    error
                );

                document.getElementById('modalReportTitle').innerText =
                    'Unable to load report';

                document.getElementById('modalReportType').innerText =
                    'N/A';

                document.getElementById('modalReportDate').innerText =
                    'N/A';

                document.getElementById('modalReportStatus').innerText =
                    'Error';

                document.getElementById('modalReportSummary').innerText =
                    error.message;

                if (typeof showToast === 'function') {
                    showToast(
                        'Unable to load report details',
                        'error'
                    );
                }
            }
        };
    });
}
async function loadReportsPage() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/reports');

        if (!response.ok) {
            throw new Error('Failed to fetch reports');
        }

        const data = await response.json();

        console.log('Reports API Response:', data);

        if (!data.success) {
            throw new Error('Failed to load reports');
        }

        const tableBody = document.getElementById('reportsTableBody');

        if (!tableBody) {
            console.error('reportsTableBody not found!');
            return;
        }

        tableBody.innerHTML = '';

        data.reports.forEach(report => {

            tableBody.innerHTML += `
                <tr>
                    <td>
                        <code>R${String(report.id).padStart(3, '0')}</code>
                    </td>

                    <td>
                        <strong>${report.name}</strong>
                    </td>

                    <td>
                        ${report.date}
                    </td>

                    <td>
                        <span class="badge success">
                            <i class="fa-solid fa-check"></i>
                            ${report.status}
                        </span>
                    </td>

                    <td>
                        <button
                            class="action-btn-sm view-report-btn"
                            data-id="${report.id}">
                            <i class="fa-solid fa-eye"></i>
                            View
                        </button>
                    </td>
                </tr>
            `;
        });

        initReportViewButtons();

        console.log('Reports loaded:', data.reports.length);

    } catch (error) {
        console.error('Reports API Error:', error);
    }
}