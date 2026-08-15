const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

const PORT = process.env.PORT || 10000;
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NVIDIA_URL =
    "https://integrate.api.nvidia.com/v1/chat/completions";

const allowedOrigins = [
    "https://tsf-g-digital-election.web.app",
    "https://tsf-g-digital-election.firebaseapp.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
];


// ==================================================
// CORS
// ==================================================

app.use(cors({
    origin: function (origin, callback) {

        // Allow requests without Origin
        // such as curl / health checks.
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        console.log("[CORS] Blocked origin:", origin);

        return callback(
            new Error("Not allowed by CORS")
        );
    },

    methods: ["GET", "POST", "OPTIONS"],

    allowedHeaders: [
        "Content-Type",
        "Accept"
    ],

    optionsSuccessStatus: 204
}));


// Express JSON parser
app.use(
    express.json({
        limit: "100kb"
    })
);


// ==================================================
// HEALTH CHECK
// ==================================================

app.get("/health", (req, res) => {

    res.status(200).json({
        ok: true,
        service: "academic-reviewer"
    });
});


// ==================================================
// ACADEMIC REVIEWER
// ==================================================

app.post("/api/academic-review", async (req, res) => {

    try {

        // --------------------------------------------------
        // Check NVIDIA API key
        // --------------------------------------------------

        if (!NVIDIA_API_KEY) {

            console.error(
                "[ACADEMIC REVIEW] NVIDIA_API_KEY is missing."
            );

            return res.status(500).json({
                error: "Server AI configuration is missing."
            });
        }


        // --------------------------------------------------
        // Get prompt
        // --------------------------------------------------

        const { prompt } = req.body || {};

        if (
            !prompt ||
            typeof prompt !== "string"
        ) {

            return res.status(400).json({
                error: "A prompt is required."
            });
        }


        console.log(
            `[ACADEMIC REVIEW] Request received from ${
                req.headers.origin || "unknown origin"
            }`
        );


        // --------------------------------------------------
        // Send request to NVIDIA
        // --------------------------------------------------

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
                            "Connect the explanation directly to the question, scenario, " +
                            "topic, competency goal, and correct answer. " +
                            "Help the student recognize the same concept when the exam " +
                            "uses a different scenario. " +
                            "Use simple, memorable wording. " +
                            "Explain why the correct answer is correct and, when relevant, " +
                            "why the other choices are incorrect. " +
                            "Do not over-explain. " +
                            "Keep the explanation clear and student-friendly."
                    },

                    {
                        role: "user",
                        content: prompt
                    }
                ],

                temperature: 1,
                top_p: 1,

                max_tokens: 400,

                // NVIDIA sends chunks because streaming is enabled.
                stream: true
            },

            {
                headers: {
                    Authorization:
                        `Bearer ${NVIDIA_API_KEY}`,

                    "Content-Type":
                        "application/json",

                    Accept:
                        "text/event-stream"
                },

                // IMPORTANT:
                // Axios must treat NVIDIA's response as a stream.
                responseType: "stream",

                timeout: 180000
            }
        );


        console.log(
            "[ACADEMIC REVIEW] NVIDIA stream connected."
        );


        // ==================================================
        // COLLECT NVIDIA STREAM
        // ==================================================

        let answer = "";
        let reasoning = "";

        let buffer = "";


        await new Promise((resolve, reject) => {

            const stream = response.data;


            stream.on("data", (chunk) => {

                try {

                    buffer += chunk.toString("utf8");


                    // SSE events are separated by blank lines.
                    const events = buffer.split("\n\n");


                    // Keep incomplete event for next chunk.
                    buffer = events.pop() || "";


                    for (const event of events) {

                        const lines =
                            event.split("\n");


                        for (const line of lines) {

                            const trimmed =
                                line.trim();


                            if (
                                !trimmed ||
                                !trimmed.startsWith("data:")
                            ) {
                                continue;
                            }


                            const data =
                                trimmed
                                    .replace(/^data:\s*/, "")
                                    .trim();


                            // NVIDIA/OpenAI streaming termination.
                            if (data === "[DONE]") {
                                continue;
                            }


                            let parsed;


                            try {

                                parsed =
                                    JSON.parse(data);

                            } catch (parseError) {

                                // Ignore malformed/incomplete
                                // SSE fragments.
                                continue;
                            }


                            const delta =
                                parsed
                                    ?.choices?.[0]
                                    ?.delta;


                            if (!delta) {
                                continue;
                            }


                            // Normal answer content
                            if (
                                typeof delta.content ===
                                "string"
                            ) {

                                answer +=
                                    delta.content;
                            }


                            // GPT-OSS reasoning content.
                            if (
                                typeof delta.reasoning_content ===
                                "string"
                            ) {

                                reasoning +=
                                    delta.reasoning_content;
                            }
                        }
                    }

                } catch (streamError) {

                    console.error(
                        "[ACADEMIC REVIEW] Stream parsing error:",
                        streamError
                    );
                }
            });


            stream.on("end", () => {

                console.log(
                    "[ACADEMIC REVIEW] NVIDIA stream finished."
                );

                resolve();
            });


            stream.on("error", (error) => {

                console.error(
                    "[ACADEMIC REVIEW] NVIDIA stream error:",
                    error
                );

                reject(error);
            });
        });


        // ==================================================
        // DEBUG INFORMATION
        // ==================================================

        console.log(
            `[ACADEMIC REVIEW] Answer length: ${answer.length}`
        );

        console.log(
            `[ACADEMIC REVIEW] Reasoning length: ${reasoning.length}`
        );


        // --------------------------------------------------
        // Check answer
        // --------------------------------------------------

        const finalAnswer =
            answer.trim();


        if (!finalAnswer) {

            console.error(
                "[ACADEMIC REVIEW] NVIDIA returned no answer content."
            );

            console.error(
                "[ACADEMIC REVIEW] Reasoning received:",
                reasoning.substring(0, 500)
            );

            return res.status(502).json({

                error:
                    "AI returned an empty response.",

                debug: {

                    answerLength:
                        answer.length,

                    reasoningLength:
                        reasoning.length,

                    reasoning:
                        reasoning.substring(0, 500)
                }
            });
        }


        // ==================================================
        // SEND RESPONSE TO FRONTEND
        // ==================================================

        console.log(
            "[ACADEMIC REVIEW] Sending final response to browser."
        );


        return res.status(200).json({

            success: true,

            answer: finalAnswer
        });


    } catch (error) {

        const details =
            error.response?.data ||
            error.message;


        console.error(
            "[NVIDIA ERROR]",
            details
        );


        return res.status(
            error.response?.status || 500
        ).json({

            error:
                "Academic reviewer request failed.",

            details:
                typeof details === "string"
                    ? details.substring(0, 1000)
                    : details
        });
    }
});


// ==================================================
// START SERVER
// ==================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Academic Reviewer backend listening on port ${PORT}`
        );
    }
);
