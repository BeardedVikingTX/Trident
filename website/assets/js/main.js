/* ==========================================================================
   TRIDENT :: Main Script
   ========================================================================== */
'use strict';

/* --------------------------------------------------------------------------
   MATRIX RAIN
   -------------------------------------------------------------------------- */
(function matrixRain() {
    const canvas = document.getElementById('matrix');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲ0123456789ABCDEFTRIDENT';
    const fontSize = 14;
    const columns  = Math.floor(canvas.width / fontSize);
    const drops    = new Array(columns).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(5, 8, 16, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff9d';
        ctx.font = fontSize + 'px JetBrains Mono, monospace';

        for (let i = 0; i < drops.length; i++) {
            const text = chars.charAt(Math.floor(Math.random() * chars.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }
    setInterval(draw, 55);
})();


/* --------------------------------------------------------------------------
   TYPEWRITER
   -------------------------------------------------------------------------- */
(function typewriter() {
    const el = document.getElementById('typing-line');
    if (!el) return;
    const cursor = el.querySelector('.cursor');

    const phrases = [
        'python cli.py ingest urls.txt',
        'python cli.py triage --ai',
        'python cli.py audit --modules sqli,ssrf,xss',
        'python cli.py report --out reports/',
        'trident --strike'
    ];

    let idx = 0, ch = 0, deleting = false;

    function setNodeText(text) {
        while (el.firstChild && el.firstChild !== cursor) el.removeChild(el.firstChild);
        el.insertBefore(document.createTextNode(text), cursor);
    }

    function tick() {
        const phrase = phrases[idx];
        if (!deleting) {
            if (ch < phrase.length) {
                ch++;
                setNodeText(phrase.slice(0, ch));
                setTimeout(tick, 55);
            } else {
                deleting = true;
                setTimeout(tick, 1800);
            }
        } else {
            if (ch > 0) {
                ch--;
                setNodeText(phrase.slice(0, ch));
                setTimeout(tick, 25);
            } else {
                deleting = false;
                idx = (idx + 1) % phrases.length;
                setTimeout(tick, 400);
            }
        }
    }
    setNodeText('');
    tick();
})();


/* --------------------------------------------------------------------------
   REVEAL ON SCROLL
   -------------------------------------------------------------------------- */
(function revealOnScroll() {
    const reveals = document.querySelectorAll('.reveal');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
    reveals.forEach((el) => observer.observe(el));
})();


/* --------------------------------------------------------------------------
   STAT COUNTERS
   -------------------------------------------------------------------------- */
(function statCounters() {
    const counters = document.querySelectorAll('.stat-number, .js-value');
    if (!counters.length) return;
    const animated = new Set();

    function animate(el) {
        if (animated.has(el)) return;
        animated.add(el);
        const target = parseInt(el.getAttribute('data-target'), 10) || 0;
        const prefix = el.getAttribute('data-prefix') || '';
        const duration = 1800;
        const start = performance.now();

        function step(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = prefix + Math.floor(target * eased).toLocaleString();
            if (progress < 1) requestAnimationFrame(step);
            else el.textContent = prefix + target.toLocaleString();
        }
        requestAnimationFrame(step);
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                if (entry.target.classList.contains('stat-number')) {
                    entry.target.closest('section')?.querySelectorAll('.stat-number').forEach(animate);
                } else {
                    animate(entry.target);
                }
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.3 });

    counters.forEach((el) => observer.observe(el));
})();


/* --------------------------------------------------------------------------
   CHARTS
   -------------------------------------------------------------------------- */
window.addEventListener('load', () => {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.font.family = 'JetBrains Mono, monospace';
    Chart.defaults.color = '#7a8a9a';

    const accent = '#00ff9d';
    const cyan   = '#00b3ff';
    const amber  = '#ffd60a';
    const red    = '#ff2d55';
    const orange = '#ff9f0a';
    const violet = '#a855f7';

    const tooltipStyle = {
        backgroundColor: '#0a0f1a',
        borderColor: accent,
        borderWidth: 1,
        titleColor: accent,
        bodyColor: '#c8d6e5',
        titleFont: { family: 'Orbitron', size: 12 },
        bodyFont:  { family: 'JetBrains Mono', size: 11 },
        padding: 12,
    };

    /* ---- INCOME JOURNEY (line chart) ---- */
    const incomeEl = document.getElementById('chart-income');
    if (incomeEl) {
        new Chart(incomeEl, {
            type: 'line',
            data: {
                labels: ['M0','M1','M2','M3','M4','M5','M6','M7','M8','M9','M10','M11','M12'],
                datasets: [
                    {
                        label: 'Without TRIDENT',
                        data: [0, 50, 80, 120, 100, 150, 200, 180, 250, 300, 350, 400, 450],
                        borderColor: '#4a5568',
                        backgroundColor: 'rgba(74,85,104,0.15)',
                        borderWidth: 2,
                        borderDash: [6, 6],
                        tension: 0.35,
                        pointRadius: 3,
                        pointBackgroundColor: '#4a5568',
                        fill: true,
                    },
                    {
                        label: 'With TRIDENT',
                        data: [0, 150, 450, 900, 1800, 3200, 4800, 6500, 8200, 9800, 11000, 12000, 12500],
                        borderColor: accent,
                        backgroundColor: 'rgba(0,255,157,0.12)',
                        borderWidth: 3,
                        tension: 0.35,
                        pointRadius: 4,
                        pointBackgroundColor: accent,
                        pointBorderColor: '#050810',
                        pointBorderWidth: 2,
                        pointHoverRadius: 7,
                        fill: true,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#c8d6e5',
                            font: { family: 'JetBrains Mono', size: 11 },
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'line',
                        }
                    },
                    tooltip: {
                        ...tooltipStyle,
                        callbacks: {
                            label: (ctx) => `${ctx.dataset.label}: $${ctx.parsed.y.toLocaleString()} / mo`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(0,255,157,0.08)' },
                        ticks: { color: '#7a8a9a', font: { size: 11 } }
                    },
                    y: {
                        grid: { color: 'rgba(0,255,157,0.08)' },
                        ticks: {
                            color: '#7a8a9a',
                            font: { size: 11 },
                            callback: (v) => '$' + v.toLocaleString()
                        }
                    }
                }
            }
        });
    }

    /* ---- PAYOUT RANGE (horizontal bar) ---- */
    const payoutEl = document.getElementById('chart-payout');
    if (payoutEl) {
        new Chart(payoutEl, {
            type: 'bar',
            data: {
                labels: ['Open Redirect', 'XSS', 'Path Traversal', 'SQLi', 'SSRF (cloud)'],
                datasets: [{
                    label: 'Typical Payout (max, $)',
                    data: [500, 3000, 5000, 8000, 12000],
                    backgroundColor: [cyan, amber, orange, red, violet],
                    borderColor: '#050810',
                    borderWidth: 2,
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...tooltipStyle,
                        callbacks: {
                            label: (ctx) => `Up to $${ctx.parsed.x.toLocaleString()}`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(0,255,157,0.08)' },
                        ticks: {
                            color: '#7a8a9a',
                            font: { size: 11 },
                            callback: (v) => '$' + v.toLocaleString()
                        }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#c8d6e5', font: { size: 11 } }
                    }
                }
            }
        });
    }

    /* ---- COVERAGE (radar) ---- */
    const coverageEl = document.getElementById('chart-coverage');
    if (coverageEl) {
        new Chart(coverageEl, {
            type: 'radar',
            data: {
                labels: [
                    'Error Detection', 'Time-Based', 'Boolean Inference',
                    'OOB Callbacks', 'Content Matching', 'Status Analysis'
                ],
                datasets: [{
                    label: 'Coverage',
                    data: [95, 88, 82, 98, 92, 78],
                    backgroundColor: 'rgba(0,255,157,0.15)',
                    borderColor: accent,
                    borderWidth: 2,
                    pointBackgroundColor: accent,
                    pointBorderColor: '#050810',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: tooltipStyle,
                },
                scales: {
                    r: {
                        angleLines: { color: 'rgba(0,255,157,0.1)' },
                        grid: { color: 'rgba(0,255,157,0.1)' },
                        pointLabels: { color: '#7a8a9a', font: { family: 'JetBrains Mono', size: 10 } },
                        ticks: { display: false, stepSize: 20 },
                        suggestedMin: 0,
                        suggestedMax: 100,
                    }
                }
            }
        });
    }
});
