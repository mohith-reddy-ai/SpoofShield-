// Required HTML element IDs:
// - textarea#email-headers
// - button#analyze-button
// - div#loading
// - div#error-message
// - div#analysis-results

document.addEventListener('DOMContentLoaded', function() {
    const emailHeadersTextarea = document.getElementById('email-headers');
    const analyzeButton = document.getElementById('analyze-button');
    const loadingDiv = document.getElementById('loading');
    const errorMessageDiv = document.getElementById('error-message');
    const analysisResultsDiv = document.getElementById('analysis-results');

    let isSubmitting = false;

    analyzeButton.addEventListener('click', async function() {
        const headers = emailHeadersTextarea.value.trim();

        if (isSubmitting) {
            return;
        }

        if (headers === '') {
            alert('Please paste the email headers.');
            return;
        }

        if (headers.length > 10000) {
            alert('The email headers are too long. Please paste a shorter version.');
            return;
        }

        isSubmitting = true;
        loadingDiv.style.display = 'block';
        errorMessageDiv.style.display = 'none';
        analysisResultsDiv.innerHTML = '';
        analyzeButton.disabled = true;

        try {
            const response = await fetch('/api/email_analyze.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ headers: headers })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            displayAnalysisResults(data);
        } catch (error) {
            loadingDiv.style.display = 'none';
            errorMessageDiv.style.display = 'block';
            errorMessageDiv.textContent = 'An error occurred while analyzing the email. Please try again later.';
        } finally {
            isSubmitting = false;
            analyzeButton.disabled = false;
        }
    });

    function displayAnalysisResults(data) {
        loadingDiv.style.display = 'none';

        const findings = `
            <p><strong>From:</strong> ${escapeHtml(data.from)}</p>
            <p><strong>Return-Path:</strong> ${escapeHtml(data.returnPath)}</p>
            <p><strong>Authentication-Results:</strong> ${escapeHtml(data.authenticationResults)}</p>
            <p><strong>SPF:</strong> ${escapeHtml(data.spf)}</p>
            <p><strong>DKIM:</strong> ${escapeHtml(data.dkim)}</p>
            <p><strong>DMARC:</strong> ${escapeHtml(data.dmarc)}</p>
            <p><strong>Risk Score:</strong> ${escapeHtml(data.riskScore)}</p>
            <p><strong>Explainable Findings:</strong> <span>${escapeHtml(data.explainableFindings)}</span></p>
            <p><strong>Notice:</strong> Analysis of pasted headers is not the same as independently verifying a sender's identity or cryptographically validating every DKIM signature.</p>
        `;

        analysisResultsDiv.innerHTML = findings;
    }

    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&")
            .replace(/</g, "<")
            .replace(/>/g, ">")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});