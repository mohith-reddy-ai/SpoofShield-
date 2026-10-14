// scanner.js (updated)
// expects: #domainInput, #scanButton, #resultContainer, #errorContainer

document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domainInput');
    const scanButton = document.getElementById('scanButton');
    const resultContainer = document.getElementById('resultContainer');
    const errorContainer = document.getElementById('errorContainer');

    if (!domainInput || !scanButton || !resultContainer) {
        console.warn('scanner.js: expected DOM elements not found.');
        return;
    }

    scanButton.addEventListener('click', async function() {
        resultContainer.innerHTML = '';
        errorContainer && (errorContainer.innerHTML = '');
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
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ domain })
            });
            if (!response.ok) {
                const txt = await response.text();
                throw new Error('Server error: ' + response.status + ' ' + txt);
            }
            const json = await response.json();
            if (!json.success) {
                throw new Error(json.message || 'Scan failed');
            }
            renderResults(json.data);
        } catch (err) {
            showErrorMessage(err.message || 'Unknown error');
        } finally {
            scanButton.disabled = false;
        }
    });

    function validateDomain(domain) {
        const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,}$/;
        return domainRegex.test(domain);
    }

    function showErrorMessage(message) {
        if (!errorContainer) return;
        const e = document.createElement('div');
        e.className = 'error';
        e.textContent = message;
        errorContainer.appendChild(e);
    }

    function renderResults(data) {
        // Highest-level
        const title = document.createElement('div');
        title.className = 'scan-summary';
        title.innerHTML = `<strong>Domain:</strong> `;
        const span = document.createElement('span');
        span.textContent = data.domain + ' — ' + data.scanned_at;
        title.appendChild(span);
        resultContainer.appendChild(title);

        // risk
        const risk = document.createElement('div');
        risk.className = 'risk';
        risk.textContent = `Risk Score: ${data.risk_score} — ${data.risk_level}`;
        resultContainer.appendChild(risk);

        // records
        const rec = data.records || {};
        ['a','aaaa','mx','ns','txt','spf','dmarc'].forEach(function(k) {
            if (!rec[k] || (Array.isArray(rec[k]) && rec[k].length === 0)) return;
            const block = document.createElement('div');
            block.className = 'finding';
            const h = document.createElement('h3');
            h.textContent = k.toUpperCase();
            block.appendChild(h);
            if (Array.isArray(rec[k])) {
                const ul = document.createElement('ul');
                rec[k].forEach(function(item) {
                    const li = document.createElement('li');
                    li.textContent = typeof item === 'string' ? item : JSON.stringify(item);
                    ul.appendChild(li);
                });
                block.appendChild(ul);
            } else {
                const p = document.createElement('p');
                p.textContent = rec[k];
                block.appendChild(p);
            }
            resultContainer.appendChild(block);
        });

        // findings + limitations
        if (data.findings && data.findings.length) {
            const fdiv = document.createElement('div');
            fdiv.innerHTML = '<h3>Findings</h3>';
            const ul = document.createElement('ul');
            data.findings.forEach(function(it) { const li = document.createElement('li'); li.textContent = it; ul.appendChild(li); });
            fdiv.appendChild(ul);
            resultContainer.appendChild(fdiv);
        }
        if (data.limitations && data.limitations.length) {
            const ldiv = document.createElement('div');
            ldiv.innerHTML = '<h3>Limitations</h3>';
            const ul = document.createElement('ul');
            data.limitations.forEach(function(it) { const li = document.createElement('li'); li.textContent = it; ul.appendChild(li); });
            ldiv.appendChild(ul);
            resultContainer.appendChild(ldiv);
        }

        // investigation id + link to report page (if present)
        if (data.investigation_id) {
            const iddiv = document.createElement('div');
            iddiv.className = 'investigation';
            const a = document.createElement('a');
            a.href = `/report.html?id=${encodeURIComponent(data.investigation_id)}`;
            a.textContent = 'View printable report';
            iddiv.appendChild(a);
            resultContainer.appendChild(iddiv);
        }
    }
});
