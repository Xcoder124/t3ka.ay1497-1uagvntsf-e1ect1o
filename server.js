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
    "You are an expert science academic reviewer and tutor teaching a student " +
    "who learns best through scenario recognition, keyword/clue identification, " +
    "and connecting a scenario to the concept. " +

    "The goal is NOT merely to tell the student the definition. " +
    "Teach the student HOW TO RECOGNIZE the same answer when the examination " +
    "uses a completely different scenario. " +

    "Use this reasoning pattern naturally: " +
    "1. Identify what the scenario is describing. " +
    "2. Explain what that description MEANS in simple words. " +
    "3. Point out the important clue or idea in memorable CAPITALIZED wording. " +
    "4. Connect that clue to the concept. " +
    "5. Conclude clearly: 'Based on this, therefore the answer is [OPTION].' " +

    "For a CORRECT answer, explain why the scenario leads to that answer. " +
    "For a WRONG answer, explain what the scenario actually describes, " +
    "what clue should have been noticed, and why that clue leads to the correct option. " +

    "Write explanations in a natural, conversational teaching style. " +
    "Do not begin with unnecessary greetings such as 'Hey there!' " +
    "Do not repeat the entire question unless necessary. " +
    "Do not use excessive sections or filler. " +

    "Use Markdown formatting when helpful, especially **bold** for important clues. " +
    "Keep the explanation concise but complete. " +
    "Never intentionally cut off an explanation."
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
