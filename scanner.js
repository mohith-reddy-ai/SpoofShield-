// DNS Scanner Script
// Required HTML IDs:
// - domainInput: Input field for the domain
// - scanButton: Button to trigger the DNS scan
// - resultContainer: Container to display the DNS scan results
// - errorContainer: Container to display error messages

document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domainInput');
    const scanButton = document.getElementById('scanButton');
    const resultContainer = document.getElementById('resultContainer');
    const errorContainer = document.getElementById('errorContainer');

    scanButton.addEventListener('click', async function() {
        // Clear previous results and errors
        resultContainer.innerHTML = '';
        errorContainer.innerHTML = '';

        // Disable the scan button during the request
        scanButton.disabled = true;

        const domain = domainInput.value.trim();
        if (!validateDomain(domain)) {
            showErrorMessage('Invalid domain name. Please enter a valid domain.');
            scanButton.disabled = false;
            return;
        }

        try {
            const response = await fetch('/api/dns_scan.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain })
            });

            if (!response.ok) {
                throw new Error('Network error. Please try again.');
            }

            const data = await response.json();
            renderResults(data);
        } catch (error) {
            showErrorMessage(error.message);
        } finally {
            scanButton.disabled = false;
        }
    });

    function validateDomain(domain) {
        // Simple domain validation regex
        const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$/;
        return domainRegex.test(domain);
    }

    function showErrorMessage(message) {
        const errorElement = document.createElement('div');
        errorElement.className = 'error';
        errorElement.textContent = message;
        errorContainer.appendChild(errorElement);
    }

    function renderResults(data) {
        // Render findings
        renderFinding('A', data.a);
        renderFinding('AAAA', data.aaaa);
        renderFinding('MX', data.mx);
        renderFinding('NS', data.ns);
        renderFinding('TXT', data.txt);
        renderFinding('SPF', data.spf);
        renderFinding('DMARC', data.dmarc);

        // Render risk score and level
        const riskScore = data.risk_score;
        const riskLevel = data.risk_level;

        const riskElement = document.createElement('div');
        riskElement.className = 'risk';
        riskElement.innerHTML = `
            <h3>Risk Score: ${encodeURIComponent(riskScore)}</h3>
            <p>Risk Level: ${encodeURIComponent(riskLevel)}</p>
        `;
        resultContainer.appendChild(riskElement);
    }

    function renderFinding(type, findings) {
        if (!findings || findings.length === 0) {
            return;
        }

        const findingElement = document.createElement('div');
        findingElement.className = 'finding';
        findingElement.innerHTML = `
            <h3>${encodeURIComponent(type)}</h3>
            <ul>
                ${findings.map(finding => `
                    <li>
                        <strong>Reason:</strong> ${encodeURIComponent(finding.reason)}<br>
                        <strong>Timestamp:</strong> ${encodeURIComponent(finding.timestamp)}<br>
                        <strong>Investigation Limitations:</strong> ${encodeURIComponent(finding.investigation_limitations)}
                    </li>
                `).join('')}
            </ul>
        `;
        resultContainer.appendChild(findingElement);
    }
});