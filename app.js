// app.js
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const tesseract = require("tesseract.js");
const dns = require("dns").promises;
const axios = require("axios");
const PDFDocument = require("pdfkit");
require("dotenv").config();

const app = express();
const PORT = 3000;

// EJS view engine
app.set("view engine", "ejs");
app.use(express.static("public"));

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// DNS-based email protection checks
async function checkSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const spf = records.flat().find(r => r.startsWith('v=spf1'));
    return spf ? "Иә (бар)" : "Жоқ";
  } catch (err) {
    return "Қате немесе табылмады";
  }
}

async function checkDMARC(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarc = records.flat().find(r => r.startsWith('v=DMARC1'));
    return dmarc ? "Иә (бар)" : "Жоқ";
  } catch (err) {
    return "Қате немесе табылмады";
  }
}

async function checkDKIM(domain, selector = 'default') {
  try {
    const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const dkim = records.flat().find(r => r.includes('v=DKIM1'));
    return dkim ? "Иә (бар)" : "Жоқ";
  } catch (err) {
    return "Қате немесе табылмады";
  }
}

// VirusTotal URL checker
async function checkVirusTotal(url) {
  const apiKey = process.env.VT_API_KEY;
  const encoded = Buffer.from(url).toString('base64').replace(/=+$/, '');
  try {
    console.log("🛡 VT кілт:", apiKey);
    console.log("🧪 VT тексеріліп жатқан URL:", url);

    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { 'x-apikey': apiKey }
    });

    console.log("📊 VT жауап:", response.data);

    const stats = response.data.data.attributes.last_analysis_stats;
    return stats;
  } catch (err) {
    console.log("❌ VT қатесі:", err.message);
    return { error: "VirusTotal қате: " + err.message };
  }
}

// GET home page
app.get("/", (req, res) => {
  res.render("index", { result: null });
});

// PDF генерациялау
app.get("/download", (req, res) => {
  const data = req.query;
  const doc = new PDFDocument();
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=result.pdf");
  doc.pipe(res);

  doc.fontSize(18).text("Фишинг талдауының нәтижесі", { align: "center" });
  doc.moveDown();

  doc.fontSize(12).text(`👤 Кімнен: ${data.from}`);
  doc.text(`📌 Тақырып: ${data.subject}`);
  doc.text(`🌐 Домен: ${data.domain}`);
  doc.text(`✅ SPF: ${data.spf}`);
  doc.text(`🔐 DKIM: ${data.dkim}`);
  doc.text(`📬 DMARC: ${data.dmarc}`);
  doc.text(`🛡 Қауіп деңгейі: ${data.risk}`);
  doc.moveDown();

  if (data.urls) {
    doc.text("🔗 Сілтемелер:");
    const urls = decodeURIComponent(data.urls).split(",");
    urls.forEach(url => {
      doc.text(" • " + url);
    });
  }

  doc.end();
});

// Қауіп шкаласын есептеу функциясы
function calculateRisk(spf, dkim, urls) {
  if (spf === "Жоқ" && dkim === "Жоқ" && urls.length > 0) return "Жоғары";
  if (dkim === "Жоқ" && urls.length > 0) return "Орташа";
  return "Қауіпсіз";
}

// POST analyze
app.post("/analyze", upload.single("file"), async (req, res) => {
  const filePath = req.file.path;
  const ext = path.extname(filePath).toLowerCase();

  let result = {};
  try {
    if ([".jpg", ".jpeg", ".png"].includes(ext)) {
      const ocr = await tesseract.recognize(filePath, "eng");
      const text = ocr.data.text;
      const suspicious = text.match(/(login|verify|reset|click here|account)/gi) || [];
      result = { type: "image", text, suspicious };
    } else if (ext === ".eml") {
      const raw = fs.readFileSync(filePath, "utf8");

      const urls = raw.match(/https?:\/\/[^\s"'>)]+/gi) || [];
      console.log("🩇 Табылған URL-дер:", urls);

      const from = raw.match(/^From: (.+)$/mi)?.[1] || "Қатені анықтау мүмкін емес";
      const subject = raw.match(/^Subject: (.+)$/mi)?.[1] || "Тақырып жоқ";

      const domainMatch = from.match(/@([\w.-]+)/);
      const domain = domainMatch ? domainMatch[1] : null;

      let spf = "Білгісіз", dkim = "Білгісіз", dmarc = "Білгісіз";
      if (domain) {
        spf = await checkSPF(domain);
        dkim = await checkDKIM(domain);
        dmarc = await checkDMARC(domain);
      }

      let vtResults = [];
      for (const url of urls) {
        const vt = await checkVirusTotal(url);
        vtResults.push({ url, vt });
      }

      const riskLevel = calculateRisk(spf, dkim, urls);

      result = { type: "eml", from, subject, urls, domain, spf, dkim, dmarc, vtResults, riskLevel };
    } else {
      result = { error: "Қолдау көрсетілмейтін файл форматы" };
    }
  } catch (err) {
    result = { error: "Файлды өңдеу кезінде қате: " + err.message };
  }

  fs.unlinkSync(filePath);
  res.render("index", { result });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});