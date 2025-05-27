const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const tesseract = require("tesseract.js");
const dns = require("dns").promises;
const axios = require("axios");
const PDFDocument = require("pdfkit");
const { simpleParser } = require("mailparser");
const session = require("express-session");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000; // <-- Вот тут изменено

// Тіркелген қолданушылар тізімі (JSON файл арқылы)
const USERS_FILE = "users.json";

// EJS және статика
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: "phishing-secret-key",
  resave: false,
  saveUninitialized: false,
}));

// ⛔ Қол жеткізуді қорғау
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

// 📁 Файл жүктеу (Multer)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// 📧 DNS-Based тексерулер
async function checkSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const spf = records.flat().find(r => r.startsWith('v=spf1'));
    return spf ? "Иә (бар)" : "Жоқ";
  } catch { return "Қате немесе табылмады"; }
}

async function checkDKIM(domain, selector = 'default') {
  try {
    const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const dkim = records.flat().find(r => r.includes('v=DKIM1'));
    return dkim ? "Иә (бар)" : "Жоқ";
  } catch { return "Қате немесе табылмады"; }
}

async function checkDMARC(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarc = records.flat().find(r => r.startsWith('v=DMARC1'));
    return dmarc ? "Иә (бар)" : "Жоқ";
  } catch { return "Қате немесе табылмады"; }
}

// 🛡 VirusTotal тексеру
async function checkVirusTotal(url) {
  const apiKey = process.env.VT_API_KEY;
  const encoded = Buffer.from(url).toString("base64").replace(/=+$/, "");
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
      headers: { "x-apikey": apiKey }
    });
    return res.data.data.attributes.last_analysis_stats;
  } catch (err) {
    return { error: "VirusTotal қатесі: " + err.message };
  }
}

// ⚖ Қауіп деңгейі
function calculateRisk(spf, dkim, urls) {
  if (spf === "Жоқ" && dkim === "Жоқ" && urls.length > 0) return "Жоғары";
  if (dkim === "Жоқ" && urls.length > 0) return "Орташа";
  return "Қауіпсіз";
}

// 📄 Басты бет
app.get("/", (req, res) => {
  res.redirect("/dashboard");
});

// 📥 Тіркелу беті
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

// 📤 Тіркелу өңдеу
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  if (users.find(u => u.username === username)) {
    return res.render("register", { error: "Мұндай пайдаланушы бар" });
  }
  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users));
  res.redirect("/login");
});

// 🔐 Кіру беті
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// 🔐 Кіру өңдеу
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE));
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render("login", { error: "Қате логин немесе құпиясөз" });
  }
  req.session.user = user.username;
  res.redirect("/dashboard");
});

// 🚪 Шығу
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// 🧾 Dashboard
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("index", { result: null, user: req.session.user });
});

// 📊 Файлды талдау
app.post("/analyze", isAuthenticated, upload.single("file"), async (req, res) => {
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
      const raw = fs.readFileSync(filePath);
      const parsed = await simpleParser(raw);
      const text = parsed.text || "";
      const html = parsed.html || "";
      const urlsText = [...text.matchAll(/https?:\/\/[^\s"'<>]+/gi)].map(m => m[0]) || [];
      const urlsHtml = [...html.matchAll(/https?:\/\/[^\s"'<>]+/gi)].map(m => m[0]) || [];
      const urls = [...new Set([...urlsText, ...urlsHtml])];
      const from = parsed.from?.text || "Кімнен ақпарат табылмады";
      const subject = parsed.subject || "Тақырып жоқ";

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
  res.render("index", { result, user: req.session.user });
});

// 📥 PDF жүктеу
app.get("/download", isAuthenticated, (req, res) => {
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
  doc.text(`🛡 Қауіп деңгейі: ${data.riskLevel}`);
  doc.moveDown();

  if (data.urls) {
    doc.text("🔗 Сілтемелер:");
    const urls = decodeURIComponent(data.urls).split(",");
    urls.forEach(url => doc.text(" • " + url));
  }

  doc.end();
});

// 🔊 Серверді іске қосу
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
