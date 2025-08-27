// server.js - Improved OCR endpoint with better error handling
import dotenv from "dotenv";
dotenv.config(); // Load environment variables from .env file
import * as jose from "jose";
import express, { response } from "express";
import bodyParser from "body-parser";
import cors from "cors";
import Tesseract from "tesseract.js";
import { createClerkClient } from "@clerk/backend";
import { GoogleGenerativeAI } from "@google/generative-ai";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
// import admin from "./admin.js";
import { createClient } from "@supabase/supabase-js";
// Supabase client (backend only)

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;
const __filename = fileURLToPath(import.meta.url);
const currentDirname = path.dirname(__filename);

// --- Multer Configuration ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(currentDirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(
      null,
      `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`
    );
  },
});

// Add file filter to only accept images
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
    "image/bmp",
    "image/webp",
  ];
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Invalid file type. Only image files are allowed."), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
});

// Check for required environment variables
const requiredEnvVars = ["GEMINI_API_KEY"];
const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error("❌ Missing required environment variables:", missingEnvVars);
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

const app = express();
const PORT = process.env.LISTEN_PORT || 3000;

const clerkClient = createClerkClient({
  secretKey: process.env.CLERK_SECRET_KEY,
  publishableKey: process.env.CLERK_PUBLIC_KEY,
});

console.log("Clerk client methods:", Object.keys(clerkClient));
app.use(cors());
app.use(bodyParser.json());

// Middleware to validate Supabase JWT
const validateSupabaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Missing or invalid token format" });
  }

  const token = authHeader.split(" ")[1];
  const secret = new TextEncoder().encode(SUPABASE_JWT_SECRET);

  try {
    const { payload } = await jose.jwtVerify(token, secret, {
      audience: "authenticated", // Standard audience for Supabase JWTs
    });

    // Attach the decoded user info to the request object
    req.user = payload;
    next(); // Token is valid, proceed to the route handler
  } catch (err) {
    console.error("JWT Verification Error:", err.message);
    return res
      .status(401)
      .json({ error: "Unauthorized: Invalid or expired token" });
  }
};

// Enhanced OCR endpoint with better error handling
app.post("/ocr", validateSupabaseToken, (req, res) => {
  // admin.auth().verifyIdToken(req.headers.authorization);

  upload.single("image")(req, res, async (uploadErr) => {
    // ... (Your existing Multer error handling) ...
    if (uploadErr) {
      console.error("❌ Multer error:", uploadErr.message);
      return res.status(400).json({
        error: "File upload failed",
        details: uploadErr.message,
      });
    }

    let worker = null;
    let filePath = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error:
            "No image file uploaded. Make sure to use 'image' as the form field name.",
        });
      }

      filePath = path.resolve(req.file.path);
      console.log("🖼️ Processing file:", filePath);

      if (!fs.existsSync(filePath)) {
        throw new Error("Uploaded file not found on server");
      }

      // --- Streamlined Tesseract Initialization ---
      console.log("🔧 Initializing Tesseract worker for Turkish OCR...");

      // Tesseract.js v5+ requires a specific language code.
      // We will only try to initialize with 'tur' as that is the user's intent.
      // The library will automatically download the language data if needed.
      worker = await Tesseract.createWorker("tur");
      console.log(
        "✅ Tesseract worker initialized with Turkish language model"
      );

      // --- Tesseract Recognition ---
      console.log("🔍 Performing OCR on the image...");
      const result = await worker.recognize(filePath);
      const rawText = result.data.text.trim();

      if (!rawText) {
        throw new Error("No text detected in the image");
      }

      console.log("📄 OCR completed, text length:", rawText.length);

      // --- Cleanup ---
      await worker.terminate();
      worker = null;
      fs.unlinkSync(filePath);
      filePath = null;

      // ... (Rest of your Gemini processing code) ...
      if (rawText.length < 10) {
        return res.json({
          ocr_result: {
            corrected_text: rawText,
            yks_topics: [],
            note: "Text too short to categorize",
          },
          raw_text: rawText,
        });
      }

      console.log("🤖 Processing with Gemini...");
      const prompt = `OCR ile bir fotoğraftan aşağıdaki yks sorusunu çıkardım, ocr sisteminden kaynaklı Yazım ve mantık hatalarını gider, metni düzeltilmiş haliyle JSON çıktısının "corrected_text" alanına ekleyin. Ayrıca, sorunun ait olduğu YKS (Yükseköğretim Kurumları Sınavı) konularını "yks_topics" alanına listeyin (örneğin: "TYT-Biyologi-Bitkiler", "AYT-Kimya-Asitler-Bazlar"). Soru çözümünü kesinlikse vermeyin.

Metin:
${rawText}`;

      const payload = {
        contents: [
          {
            parts: [{ text: prompt }],
          },
        ],
        generationConfig: {
          responseMimeType: "application/json",
          responseSchema: {
            type: "OBJECT",
            properties: {
              corrected_text: { type: "STRING" },
              yks_topics: {
                type: "ARRAY",
                items: { type: "STRING" },
              },
              note: { type: "STRING" },
            },
            required: ["corrected_text", "yks_topics"],
          },
        },
      };

      // ... (Rest of your Gemini API call and response handling) ...
      console.log("📤 Sending request to Gemini API...");
      let geminiResponse;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);
        geminiResponse = await Promise.race([
          model.generateContent(payload),
          new Promise((_, reject) =>
            setTimeout(
              () => reject(new Error("Gemini API timeout after 30 seconds")),
              30000
            )
          ),
        ]);
        clearTimeout(timeoutId);
        console.log("📥 Received response from Gemini API");
      } catch (geminiError) {
        // ... (Your existing Gemini error handling) ...
        console.error("❌ Gemini API Error:", geminiError);
        console.log("⚠️ Returning OCR-only result due to Gemini failure");
        return res.json({
          ocr_result: {
            corrected_text: rawText,
            yks_topics: [],
            note: "AI processing unavailable - raw OCR result returned",
          },
          raw_text: rawText,
          success: true,
          warning: "AI processing failed, OCR completed successfully",
        });
      }

      // ... (Rest of your response parsing and final JSON response) ...
      let structuredData;
      try {
        const responseText =
          geminiResponse.response.candidates[0].content.parts[0].text;
        structuredData = JSON.parse(responseText);
      } catch (parseErr) {
        console.error(
          "❌ Failed to parse Gemini response as JSON:",
          parseErr.message
        );
        structuredData = {
          corrected_text: rawText,
          yks_topics: [],
          note: "Failed to process with AI, returning raw OCR result",
        };
      }

      console.log("✅ Processing completed successfully");
      res.json({
        ocr_result: structuredData,
        raw_text: rawText,
        success: true,
      });
    } catch (err) {
      // ... (Your existing error cleanup and response) ...
      console.error("❌ OCR endpoint error:", err);
      if (worker) {
        try {
          await worker.terminate();
        } catch (workerErr) {
          console.error("❌ Error terminating worker:", workerErr);
        }
      }
      if (filePath && fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (unlinkErr) {
          console.error("❌ Error deleting file:", unlinkErr);
        }
      }
      const errorResponse = {
        error: "OCR processing failed",
        details: err.message,
        success: false,
      };
      const statusCode = err.message.includes("No text detected") ? 422 : 500;
      res.status(statusCode).json(errorResponse);
    }
  });
});

// Test endpoint to verify server is running
app.get("/", (req, res) => {
  res.json({
    message: "OCR Server is running",
    endpoints: ["/ocr", "/health", "/signup", "/signin"],
  });
});

// app.post("/signin", async (req, res) => {
//   try {
//     const { idToken } = req.body;
//     if (!idToken) return res.status(400).json({ error: "Missing idToken" });

//     const decoded = await admin.auth().verifyIdToken(idToken);
//     const firebase_uid = decoded.uid;
//     const email = decoded.email ?? null;
//     const name = decoded.name ?? null;

//     // Upsert user and get the UUID id
//     const { data: userData, error } = await supabase
//       .from("profiles")
//       .upsert({ firebase_uid, email, name }, { onConflict: "firebase_uid" })
//       .select("id") // Select the UUID id
//       .single();

//     if (error) {
//       console.error("DB error:", error);
//       return res.status(500).json({ error: "Profile upsert failed" });
//     }

//     // Use the UUID as sub
//     const supabaseToken = await new jose.SignJWT({
//       role: "authenticated",
//       aud: "authenticated",
//       sub: userData.id, // Use the UUID from database
//       firebase_uid, // Keep as custom claim
//     })
//       .setProtectedHeader({ alg: "HS256" })
//       .setIssuedAt()
//       .setExpirationTime("1h")
//       .sign(new TextEncoder().encode(SUPABASE_JWT_SECRET));

//     res.json({ supabaseToken });
//   } catch (err) {
//     console.error("Backend error:", err);
//     res.status(500).json({ error: "Signin failed" });
//   }
// });

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📋 Available endpoints:`);
  console.log(`   GET  /          - Server info`);
  console.log(`   GET  /health    - Health check`);
  console.log(`   POST /ocr       - OCR processing`);
  console.log(`   POST /signup    - User signup`);
  console.log(`   POST /signin    - User signin`);
});
