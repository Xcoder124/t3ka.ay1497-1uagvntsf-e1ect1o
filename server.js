const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

const PORT = process.env.PORT || 10000;
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";

const allowedOrigins = [
    "https://tsf-g-digital-election.web.app",
    "https://tsf-g-digital-election.firebaseapp.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
];

// IMPORTANT: CORS must be registered BEFORE your routes.
app.use(cors({
    origin: function (origin, callback) {
        // Requests without an Origin header
        // are allowed (curl, Render health checks, etc.)
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        console.log("Blocked CORS origin:", origin);
        return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"],
    optionsSuccessStatus: 204
}));

// Explicitly handle preflight requests.
app.options("*", cors());

app.use(express.json({ limit: "100kb" }));


// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        service: "academic-reviewer"
    });
});


// --------------------------------------------------
// ACADEMIC REVIEWER
// --------------------------------------------------

app.post("/api/academic-review", async (req, res) => {
    try {

        if (!NVIDIA_API_KEY) {
            console.error("NVIDIA_API_KEY is not configured.");

            return res.status(500).json({
                error: "Server AI configuration is missing."
            });
        }

        const { prompt } = req.body || {};

        if (!prompt || typeof prompt !== "string") {
            return res.status(400).json({
                error: "A prompt is required."
            });
        }

        console.log(
            `[ACADEMIC REVIEW] Request received from ${req.headers.origin || "unknown origin"}`
        );

        const response = await axios.post(
            NVIDIA_URL,
            {
                model: "openai/gpt-oss-120b",

                messages: [
                    {
                        role: "system",
                        content:
                            "You are an expert science academic reviewer and tutor. " +
                            "Teach through scenario recognition and reasoning. " +
                            "Respond clearly and naturally."
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],

                temperature: 1,
                top_p: 1,
                max_tokens: 400,
                stream: true
            },
            {
                headers: {
                    Authorization: `Bearer ${NVIDIA_API_KEY}`,
                    "Content-Type": "application/json",
                    Accept: "application/json"
                },

                timeout: 180000
            }
        );

        const answer =
            response.data?.choices?.[0]?.message?.content;

        if (!answer) {

            console.error(
                "NVIDIA returned no message content:",
                response.data
            );

            return res.status(502).json({
                error: "AI returned an empty response."
            });
        }

        console.log("[ACADEMIC REVIEW] NVIDIA response received.");

        return res.json({
            success: true,
            answer: answer.trim()
        });

    } catch (error) {

        const details =
            error.response?.data ||
            error.message;

        console.error(
            "[NVIDIA/KIMI ERROR]",
            details
        );

        return res.status(
            error.response?.status || 500
        ).json({
            error: "Academic reviewer request failed.",
            details:
                typeof details === "string"
                    ? details.substring(0, 500)
                    : details
        });
    }
});


// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `Academic Reviewer backend listening on port ${PORT}`
    );
});
