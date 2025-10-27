// Live clock
function updateClock() {
    const clock = document.getElementById('clock');
    setInterval(() => {
        const now = new Date();
        clock.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
    }, 1000);
}

// Threat modal
window.showDetails = function(name, type, level, timestamp) {
    const modal = document.getElementById('modal');
    const content = document.getElementById('modal-content');
    content.innerHTML = `<b>Name:</b> ${name}<br><b>Type:</b> ${type}<br><b>Level:</b> ${level}<br><b>When:</b> ${timestamp}`;
    modal.style.display = 'block';
};
window.closeModal = function() {
    document.getElementById('modal').style.display = 'none';
};

document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    // Status bar
    document.getElementById('mode-indicator').textContent = 'OFFLINE MODE';
    document.getElementById('mode-indicator').classList.add('offline');

    // Chart.js Threat Level Pie
    if (typeof chartData !== "undefined") {
        const ctx = document.getElementById('levelChart').getContext('2d');
        if(window.levelChart && typeof window.levelChart.destroy === "function"){ window.levelChart.destroy(); }

        window.levelChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: chartData.labels,
                datasets: [{
                    data: chartData.values,
                    backgroundColor: ['#db2929','#e0db29','#299ddb','#29db29']
                }]
            },
            options: {
                responsive: false,
                plugins: { legend: { labels: { color: '#33ff33', font: { size: 16 }}}},
            }
        });
    }

    // Map (Leaflet)
    if(typeof geoPoints!== "undefined" && document.getElementById('map')){
        var map = L.map('map').setView([30, 80], 2.4);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
        geoPoints.forEach(function(g){L.marker([g.lat,g.lng]).addTo(map).bindPopup(g.label);});
    }

    // Lookup
    const queryInput = document.getElementById('threat-query');
    const searchBtn = document.getElementById('search-btn');
    const resultBox = document.getElementById('lookup-result');
    searchBtn.onclick = async () => {
        const query = queryInput.value.trim();
        if (!query) { resultBox.textContent = ""; return; }
        resultBox.textContent = "Searching...";
        const res = await fetch('/lookup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({query})
        });
        const data = await res.json();
        resultBox.textContent = [
            `Query: ${data.query}`,
            `Type: ${data.threat_type}`,
            `Severity: ${data.reputation}`,
            `Details: ${data.details}`
        ].join('\n');
    };

    // Add threat form
    document.getElementById('add-form').onsubmit = async function(e){
        e.preventDefault();
        const name = document.getElementById('add-name').value;
        const type = document.getElementById('add-type').value;
        const level = document.getElementById('add-level').value;
        await fetch('/add_threat', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({name, type, level})
        });
        reloadFeed();
        this.reset();
    };

    // Feed auto-refresh
    async function reloadFeed(){
        const resp = await fetch('/feed');
        const data = await resp.json();
        let tb = document.querySelector('#feed-table tbody');
        tb.innerHTML = "";
        for(const t of data.feed){
            let tr = document.createElement('tr');
            tr.onclick = ()=> showDetails(t.name,t.type,t.level,t.timestamp);
            tr.innerHTML = `<td>${t.name}</td><td>${t.type}</td><td>${t.level}</td><td>${t.timestamp}</td>`;
            tb.appendChild(tr);
        }
        // Update chart
        if(window.levelChart){
            window.levelChart.data.datasets[0].data = [
                data.summary.critical,
                data.summary.high,
                data.summary.medium,
                data.summary.low
            ];
            window.levelChart.update();
        }
    }
    setInterval(reloadFeed, 20000); // Every 20 sec
});

