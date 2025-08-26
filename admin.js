// server.js - Improved OCR endpoint with better error handling
import dotenv from "dotenv";
dotenv.config(); // Load environment variables from .env file
import admin from "firebase-admin";

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_JSON);

// 🔑 Fix private key newlines (important!)
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
console.log("emir deneme");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

export default admin;
