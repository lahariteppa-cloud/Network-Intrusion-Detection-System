// ===============================
// SIGNUP
// ===============================

document.getElementById("signupForm")?.addEventListener("submit", async function (event) {

    event.preventDefault();

    const full_name = document.getElementById("full_name").value;
    const email = document.getElementById("email").value;
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const confirm_password = document.getElementById("confirm_password").value;

    try {

        const response = await fetch("http://127.0.0.1:5000/api/signup", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                full_name: full_name,
                email: email,
                username: username,
                password: password,
                confirm_password: confirm_password
            })
        });

        const result = await response.json();

        alert(result.message);

        if (result.success) {
            window.location.href = "login.html";
        }

    } catch (error) {

        console.error("Signup Error:", error);

        alert("Cannot connect to NIDS backend. Make sure Flask is running.");

    }

});


// ===============================
// LOGIN
// ===============================

document.getElementById("loginForm")?.addEventListener("submit", async function (event) {

    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {

        const response = await fetch("http://127.0.0.1:5000/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        const result = await response.json();

        alert(result.message);

        if (result.success) {

            window.location.href = "dashboard.html";

        } else {

            alert("Login failed. Please check your credentials.");

        }

    } catch (error) {

        console.error("Login Error:", error);

        alert("Cannot connect to NIDS backend. Make sure Flask is running.");

    }

});


// ===============================
// DASHBOARD STATISTICS
// ===============================

document.addEventListener("DOMContentLoaded", async function () {

    if (!document.getElementById("totalTraffic")) {
        return;
    }

    try {

        const response = await fetch("http://127.0.0.1:5000/api/dashboard");

        const result = await response.json();

        if (result.success) {

            document.getElementById("totalTraffic").textContent =
                result.total_traffic.toLocaleString();

            document.getElementById("threatsDetected").textContent =
                result.threats_detected;

            document.getElementById("detectionAccuracy").textContent =
                result.detection_accuracy + "%";

            document.getElementById("blockedIPs").textContent =
                result.blocked_ips;

        }

    } catch (error) {

        console.error("Dashboard Error:", error);

    }

});


// ===============================
// DASHBOARD RECENT ALERTS
// ===============================

document.addEventListener("DOMContentLoaded", async function () {

    if (!document.getElementById("recentAlerts")) {
        return;
    }

    try {

        const response = await fetch("http://127.0.0.1:5000/api/alerts");

        const result = await response.json();

        if (result.success) {

            const tableBody = document.getElementById("recentAlerts");

            tableBody.innerHTML = "";

            result.alerts.forEach(function (alert) {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${alert.time}</td>
                    <td>${alert.attack_type}</td>
                    <td>${alert.status}</td>
                `;

                tableBody.appendChild(row);

            });

        }

    } catch (error) {

        console.error("Dashboard Alerts Error:", error);

        document.getElementById("recentAlerts").innerHTML = `
            <tr>
                <td colspan="3">Unable to load alerts</td>
            </tr>
        `;

    }

});


// ===============================
// ALERTS PAGE
// ===============================

document.addEventListener("DOMContentLoaded", async function () {

    if (!document.getElementById("alertsContainer")) {
        return;
    }

    try {

        const response = await fetch("http://127.0.0.1:5000/api/alerts");

        const result = await response.json();

        if (result.success) {

            document.getElementById("totalAlerts").textContent =
                result.total_alerts;

            document.getElementById("highRisk").textContent =
                result.high_risk;

            document.getElementById("mediumRisk").textContent =
                result.medium_risk;

            document.getElementById("lowRisk").textContent =
                result.low_risk;


            const container = document.getElementById("alertsContainer");

            container.innerHTML = "";


            result.alerts.forEach(function (alert) {

                let cardClass = "info";
                let icon = "🔵";

                if (alert.attack_type === "DDoS Attack") {

                    cardClass = "high";
                    icon = "🔴";

                } else if (alert.attack_type === "SQL Injection") {

                    cardClass = "medium";
                    icon = "🟠";

                } else if (alert.attack_type === "Brute Force Attack") {

                    cardClass = "low";
                    icon = "🟢";

                } else if (alert.attack_type === "Port Scan") {

                    cardClass = "info";
                    icon = "🔵";

                }


                const alertCard = document.createElement("div");

                alertCard.className = "alert-card " + cardClass;

                alertCard.innerHTML = `
                    <h3>${icon} ${alert.attack_type}</h3>

                    <p>
                        <strong>IP Address:</strong>
                        ${alert.ip_address}
                    </p>

                    <p>
                        <strong>Time:</strong>
                        ${alert.time}
                    </p>

                    <span>${alert.status}</span>
                `;

                container.appendChild(alertCard);

            });

        }

    } catch (error) {

        console.error("Alerts Page Error:", error);

        document.getElementById("alertsContainer").innerHTML = `
            <p>Unable to load security alerts.</p>
        `;

    }

});


// ===============================
// REPORTS PAGE
// ===============================

document.addEventListener("DOMContentLoaded", async function () {

    const reportsContainer = document.getElementById("reportsContainer");

    if (!reportsContainer) {
        return;
    }

    try {

        const response = await fetch("http://127.0.0.1:5000/api/reports");

        const result = await response.json();

        if (result.success) {

            reportsContainer.innerHTML = "";

            result.reports.forEach(function (report) {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>R00${report.id}</td>
                    <td>${report.name}</td>
                    <td>${report.date}</td>
                    <td>${report.status}</td>
                    <td>
                        <button onclick="viewReport(${report.id})">
                            View
                        </button>
                    </td>
                `;

                reportsContainer.appendChild(row);

            });

        } else {

            reportsContainer.innerHTML = `
                <tr>
                    <td colspan="5">Unable to load reports.</td>
                </tr>
            `;

        }

    } catch (error) {

        console.error("Reports Error:", error);

        reportsContainer.innerHTML = `
            <tr>
                <td colspan="5">
                    Cannot connect to NIDS backend.
                </td>
            </tr>
        `;

    }

});


// ===============================
// VIEW REPORT
// ===============================

function viewReport(reportId) {

    alert("Report ID: R00" + reportId);

}


// ===============================
// FORGOT PASSWORD
// ===============================

document.getElementById("forgotPasswordForm")?.addEventListener("submit", async function (event) {

    event.preventDefault();

    const username = document.getElementById("username").value;
    const email = document.getElementById("email").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    try {

        const response = await fetch(
            "http://127.0.0.1:5000/api/forgot-password",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                })
            }
        );

        const result = await response.json();

        alert(result.message);

        if (result.success) {

            window.location.href = "login.html";

        }

    } catch (error) {

        console.error("Forgot Password Error:", error);

        alert("Cannot connect to NIDS backend. Make sure Flask is running.");

    }

});