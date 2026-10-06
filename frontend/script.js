console.log("Password Analyzer JavaScript loaded");


/* -----------------------------------
   GET HTML ELEMENTS
----------------------------------- */

const passwordInput =
    document.getElementById("passwordInput");

const togglePassword =
    document.getElementById("togglePassword");

const analyzeButton =
    document.getElementById("analyzeButton");

const generateButton =
    document.getElementById("generateButton");

const generatedPassword =
    document.getElementById("generatedPassword");

const copyButton =
    document.getElementById("copyButton");

const resultSection =
    document.getElementById("resultSection");

const connectionError =
    document.getElementById("connectionError");

const scoreElement =
    document.getElementById("score");

const classificationElement =
    document.getElementById("classification");

const strengthFill =
    document.getElementById("strengthFill");

const findingsElement =
    document.getElementById("findings");

const suggestionsElement =
    document.getElementById("suggestions");

const policyResults =
    document.getElementById("policyResults");

const metricLength =
    document.getElementById("metricLength");

const metricTypes =
    document.getElementById("metricTypes");

const metricUnique =
    document.getElementById("metricUnique");

const metricRatio =
    document.getElementById("metricRatio");

const metricEntropy =
    document.getElementById("metricEntropy");

const summaryLength =
    document.getElementById("summaryLength");

const summaryTypes =
    document.getElementById("summaryTypes");

const summaryEntropy =
    document.getElementById("summaryEntropy");

const summaryScore =
    document.getElementById("summaryScore");

const scoreChartCanvas =
    document.getElementById("scoreChart");


/* -----------------------------------
   CHART VARIABLE
----------------------------------- */

let scoreChart = null;


/* -----------------------------------
   SHOW / HIDE PASSWORD
----------------------------------- */

togglePassword.addEventListener("click", function () {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";

        togglePassword.textContent = "Hide";

    } else {

        passwordInput.type = "password";

        togglePassword.textContent = "Show";

    }

});


/* -----------------------------------
   ANALYZE PASSWORD
----------------------------------- */

async function analyzePassword() {

    const password = passwordInput.value;


    // Empty password
    if (password.length === 0) {

        resultSection.style.display = "none";

        connectionError.style.display = "none";

        return;

    }


    // Hide old error
    connectionError.style.display = "none";


    try {

        console.log("Sending password to Flask...");


        const response = await fetch("/api/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                password: password
            })

        });


        console.log("Flask response:", response.status);


        if (!response.ok) {

            throw new Error(
                "Server returned error " + response.status
            );

        }


        const data = await response.json();


        console.log("Analyzer result:", data);


        displayResults(data);


    } catch (error) {

        console.error(
            "Connection error:",
            error
        );

        resultSection.style.display = "none";

        connectionError.style.display = "block";

    }

}


/* -----------------------------------
   DISPLAY RESULTS
----------------------------------- */

function displayResults(data) {

    resultSection.style.display = "block";


    /* SCORE */

    const score = data.score || 0;

    scoreElement.textContent = score;


    /* CLASSIFICATION */

    const classification =
        data.classification || "UNKNOWN";

    classificationElement.textContent =
        classification;


    /* STRENGTH BAR */

    /* STRENGTH BAR */

strengthFill.style.width =
    score + "%";


/* CHANGE STRENGTH BAR COLOR */

if (classification === "VERY WEAK") {

    strengthFill.style.background = "#d32f2f";

} else if (classification === "WEAK") {

    strengthFill.style.background = "#f57c00";

} else if (classification === "MODERATE") {

    strengthFill.style.background = "#fbc02d";

} else if (classification === "STRONG") {

    strengthFill.style.background = "#388e3c";

} else if (classification === "VERY STRONG") {

    strengthFill.style.background = "#1976d2";

}


    /* -----------------------------------
       FINDINGS
    ----------------------------------- */

    findingsElement.innerHTML = "";


    if (
        data.findings &&
        data.findings.length > 0
    ) {

        data.findings.forEach(function (finding) {

            const li =
                document.createElement("li");

            li.textContent = finding;

            findingsElement.appendChild(li);

        });

    }


    /* -----------------------------------
       SUGGESTIONS
    ----------------------------------- */

    suggestionsElement.innerHTML = "";


    if (
        data.suggestions &&
        data.suggestions.length > 0
    ) {

        data.suggestions.forEach(function (suggestion) {

            const li =
                document.createElement("li");

            li.textContent = suggestion;

            suggestionsElement.appendChild(li);

        });

    }


    /* -----------------------------------
       METRICS
    ----------------------------------- */

    const metrics = data.metrics || {};

    metricLength.textContent =
        metrics.length ?? "-";


    let characterTypes = 0;

    if (metrics.lowercase) {
        characterTypes++;
    }

    if (metrics.uppercase) {
        characterTypes++;
    }

    if (metrics.digits) {
        characterTypes++;
    }

    if (metrics.symbols) {
        characterTypes++;
    }


    metricTypes.textContent =
        characterTypes + " / 4";


    metricUnique.textContent =
        metrics.unique_characters ?? "-";


    if (metrics.unique_ratio !== undefined) {

        metricRatio.textContent =
            Math.round(metrics.unique_ratio * 100) + "%";

    } else {

        metricRatio.textContent = "-";

    }


    metricEntropy.textContent =
        metrics.entropy !== undefined
            ? metrics.entropy + " bits"
            : "-";


    /* -----------------------------------
       POLICY
    ----------------------------------- */

    policyResults.innerHTML = "";


    const policy = data.policy || {};


    const policyRules = [

        ["minimum_length", "At least 12 characters"],

        ["maximum_length", "Maximum 128 characters"],

        ["has_lowercase", "Contains lowercase letters"],

        ["has_uppercase", "Contains uppercase letters"],

        ["has_digit", "Contains numbers"],

        ["has_symbol", "Contains symbols"]

    ];


    policyRules.forEach(function ([key, label]) {

        const li =
            document.createElement("li");


        if (policy[key]) {

            li.textContent =
                "✓ " + label;

            li.className = "policy-pass";

        } else {

            li.textContent =
                "✗ " + label;

            li.className = "policy-fail";

        }


        policyResults.appendChild(li);

    });


    /* -----------------------------------
       SUMMARY
    ----------------------------------- */

    summaryLength.textContent =
        metrics.length ?? "-";

    summaryTypes.textContent =
        characterTypes + " / 4";

    summaryEntropy.textContent =
        metrics.entropy !== undefined
            ? metrics.entropy + " bits"
            : "-";

    summaryScore.textContent =
        score;


    /* -----------------------------------
       CHART
    ----------------------------------- */

    createScoreChart(score);

}


/* -----------------------------------
   CREATE SCORE CHART
----------------------------------- */

function createScoreChart(score) {

    if (!scoreChartCanvas) {
        return;
    }


    if (scoreChart !== null) {

        scoreChart.destroy();

    }


    scoreChart =
        new Chart(scoreChartCanvas, {

            type: "doughnut",

            data: {

                labels: [
                    "Security Score",
                    "Remaining"
                ],

                datasets: [

                    {

                        data: [
                            score,
                            100 - score
                        ]

                    }

                ]

            },

            options: {

                responsive: true,

                plugins: {

                    legend: {
                        position: "bottom"
                    }

                }

            }

        });

}


/* -----------------------------------
   ANALYZE BUTTON
----------------------------------- */

analyzeButton.addEventListener(
    "click",
    analyzePassword
);


/* -----------------------------------
   REAL-TIME ANALYSIS
----------------------------------- */

passwordInput.addEventListener(
    "input",
    function () {

        if (passwordInput.value.length > 0) {

            analyzePassword();

        } else {

            resultSection.style.display =
                "none";

            connectionError.style.display =
                "none";

        }

    }
);


/* -----------------------------------
   GENERATE PASSWORD
----------------------------------- */

generateButton.addEventListener(
    "click",
    async function () {

        try {

            const response =
                await fetch(
                    "/api/generate-password",
                    {

                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            length: 16
                        })

                    }
                );


            if (!response.ok) {

                throw new Error(
                    "Generator request failed"
                );

            }


            const data =
                await response.json();


            generatedPassword.value =
                data.password;


        } catch (error) {

            console.error(
                "Generator error:",
                error
            );

            alert(
                "Could not generate password."
            );

        }

    }
);


/* -----------------------------------
   COPY GENERATED PASSWORD
----------------------------------- */

copyButton.addEventListener(
    "click",
    async function () {

        const password =
            generatedPassword.value;


        if (!password) {

            return;

        }


        try {

            await navigator.clipboard.writeText(
                password
            );

            copyButton.textContent =
                "Copied!";


            setTimeout(function () {

                copyButton.textContent =
                    "Copy";

            }, 1500);


        } catch (error) {

            console.error(
                "Copy error:",
                error
            );

        }

    }
);