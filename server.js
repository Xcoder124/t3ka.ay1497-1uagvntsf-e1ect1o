const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

const PORT = process.env.PORT || 10000;
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";

// Set FRONTEND_URL in Render to your Firebase Hosting URL.
// Example: https://tsf-g-digital-election.web.app
const allowedOrigins = [
    process.env.FRONTEND_URL,
    "http://127.0.0.1:5500",
    "http://localhost:5500"
].filter(Boolean);

app.use(cors({
    origin(origin, callback) {
        // Allow non-browser/server requests with no Origin.
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error(`CORS blocked origin: ${origin}`));
    },
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"]
}));

app.use(express.json({ limit: "100kb" }));

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        service: "academic-reviewer",
        provider: "NVIDIA Kimi"
    });
});

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

        // The backend constructs the actual Kimi request.
        // The browser never sees the NVIDIA API key.
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
                max_tokens: 700,
temperature: 0.2,
top_p: 0.8,
stream: false,
                chat_template_kwargs: {
                    thinking: false
                }
            },
            {
                headers: {
                    Authorization: `Bearer ${NVIDIA_API_KEY}`,
                    "Content-Type": "application/json",
                    Accept: "application/json"
                },
                timeout: 90000
            }
        );

        const answer =
            response.data?.choices?.[0]?.message?.content;

        if (!answer) {
            console.error("NVIDIA returned no message content:", response.data);
            return res.status(502).json({
                error: "AI returned an empty response."
            });
        }

        return res.json({
            success: true,
            answer: answer.trim()
        });

    } catch (error) {
        const details = error.response?.data || error.message;

        console.error("[NVIDIA/KIMI ERROR]", details);

        return res.status(error.response?.status || 500).json({
            error: "Academic reviewer request failed.",
            details:
                typeof details === "string"
                    ? details.substring(0, 500)
                    : details
        });
    }
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Academic Reviewer backend listening on port ${PORT}`);
});
