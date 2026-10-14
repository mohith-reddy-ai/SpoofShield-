// assets/js/reports.js

document.addEventListener('DOMContentLoaded', () => {
    const reportContainer = document.getElementById('reportContainer');
    const printButton = document.getElementById('printButton');
    const reportId = new URLSearchParams(window.location.search).get('id');

    if (!reportId) {
        reportContainer.innerHTML = '<p>No report selected.</p>';
        return;
    }

    fetch(`/api/report.php?id=${encodeURIComponent(reportId)}`)
        .then(response => response.json())
        .then(data => displayReport(data))
        .catch(error => displayError(error));

    printButton.addEventListener('click', () => {
        const printLayout = createPrintLayout(data);
        document.body.appendChild(printLayout);
        window.print();
        document.body.removeChild(printLayout);
    });

    function displayReport(data) {
        if (!data) {
            reportContainer.innerHTML = '<p>Report not found.</p>';
            return;
        }

        reportContainer.innerHTML = `
            <h1>${data.target}</h1>
            <p><strong>Investigation Type:</strong> ${data.type}</p>
            <p><strong>Risk Score:</strong> ${data.risk_score}</p>
            <p><strong>Risk Level:</strong> ${data.risk_level}</p>
            <p><strong>Timestamp:</strong> ${data.timestamp}</p>
            <h2>Findings</h2>
            <div>${safeRenderText(data.findings)}</div>
            <h2>Limitations</h2>
            <div>${safeRenderText(data.limitations)}</div>
        `;
    }

    function displayError(error) {
        reportContainer.innerHTML = `<p>Error: ${error.message}</p>`;
    }

    function safeRenderText(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function createPrintLayout(data) {
        const printLayout = document.createElement('div');
        printLayout.classList.add('print-layout');
        printLayout.innerHTML = `
            <h1>${data.target}</h1>
            <p><strong>Investigation Type:</strong> ${data.type}</p>
            <p><strong>Risk Score:</strong> ${data.risk_score}</p>
            <p><strong>Risk Level:</strong> ${data.risk_level}</p>
            <p><strong>Timestamp:</strong> ${data.timestamp}</p>
            <h2>Findings</h2>
            <div>${safeRenderText(data.findings)}</div>
            <h2>Limitations</h2>
            <div>${safeRenderText(data.limitations)}</div>
        `;
        return printLayout;
    }
});