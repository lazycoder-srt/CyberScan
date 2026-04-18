document.addEventListener("DOMContentLoaded", function() {
    const bar = document.querySelector(".progress-bar");

    if (bar) {
        let score = bar.getAttribute("data-score");
        bar.style.width = score + "%";
    }
});
document.getElementById("scan-form").addEventListener("submit", function(e) {
    e.preventDefault(); // stop instant submit

    let loading = document.getElementById("loading-section");
    let progressBar = document.getElementById("progress-bar");
    let scanText = document.getElementById("scan-text");

    loading.style.display = "block";

    let progress = 0;

    let steps = [
        "Initializing Scan...",
        "Reading File...",
        "Analyzing Hash...",
        "Checking Database...",
        "Detecting Threats...",
        "Finalizing..."
    ];

    let interval = setInterval(() => {
        progress += 10;
        progressBar.style.width = progress + "%";
        progressBar.innerText = progress + "%";

        let stepIndex = Math.floor(progress / 20);
        if (steps[stepIndex]) {
            scanText.innerText = steps[stepIndex];
        }

        if (progress >= 100) {
            clearInterval(interval);

            // submit AFTER animation
            setTimeout(() => {
                e.target.submit();
            }, 500);
        }

    }, 300);
});
// Animate result bar AFTER page loads
window.addEventListener("load", () => {
    let bar = document.getElementById("final-bar");

    if (bar) {
        let score = bar.getAttribute("data-score");

        setTimeout(() => {
            bar.style.width = score + "%";
            bar.innerText = score + "%";

            // color logic
            if (score > 70) {
                bar.style.background = "linear-gradient(90deg, #ff4d4d, #ff0000)";
            } else {
                bar.style.background = "linear-gradient(90deg, #00ffcc, #00cc99)";
            }

        }, 500);
    }
});
// handle BOTH bars (file + website)
window.addEventListener("load", () => {
    let bars = document.querySelectorAll(".progress-bar");

    bars.forEach(bar => {
        let score = parseInt(bar.getAttribute("data-score"));

        if (!isNaN(score)) {
            setTimeout(() => {
                bar.style.width = score + "%";
                bar.innerText = score + "%";

                if (score > 70) {
                    bar.style.background = "linear-gradient(90deg, #ff4d4d, #ff0000)";
                } else {
                    bar.style.background = "linear-gradient(90deg, #00ffcc, #00cc99)";
                }
            }, 300);
        }
    });
});
