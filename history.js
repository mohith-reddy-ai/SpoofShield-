// assets/js/history.js

document.addEventListener('DOMContentLoaded', () => {
    const historyContainer = document.getElementById('historyContainer');
    const dnsCheckbox = document.getElementById('dnsCheckbox');
    const emailCheckbox = document.getElementById('emailCheckbox');

    fetch('/api/history.php')
        .then(response => response.json())
        .then(data => displayHistory(data))
        .catch(error => displayError(error));

    dnsCheckbox.addEventListener('change', () => filterHistory());
    emailCheckbox.addEventListener('change', () => filterHistory());

    function displayHistory(data) {
        if (data.length === 0) {
            historyContainer.innerHTML = '<p>No investigations found.</p>';
            return;
        }

        historyContainer.innerHTML = data
            .filter(filter investigationsByType)
            .map(investigation => `
                <div class="investigation" data-id="${investigation.id}">
                    <span>${investigation.timestamp}</span>
                    <span>${investigation.type}</span>
                    <span>${investigation.target}</span>
                    <span>Risk Score: ${investigation.risk_score}</span>
                    <span>Risk Level: ${investigation.risk_level}</span>
                    <a href="report.html?id=${investigation.id}">View Report</a>
                </div>
            `)
            .join('');
    }

    function displayError(error) {
        historyContainer.innerHTML = `<p>Error: ${error.message}</p>`;
    }

    function filterInvestigationsByType(investigation) {
        return (
            (!dnsCheckbox.checked || investigation.type === 'DNS') &&
            (!emailCheckbox.checked || investigation.type === 'Email')
        );
    }

    function filterHistory() {
        fetch('/api/history.php')
            .then(response => response.json())
            .then(data => displayHistory(data))
            .catch(error => displayError(error));
    }
});