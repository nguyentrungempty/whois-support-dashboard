const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;
const { exec } = require("child_process");
const cheerio = require("cheerio");

const app = express();
const PORT = 3001;

/* ============================= */
/* ===== WHOIS PARSER ========= */
/* ============================= */

function parseWhois(text) {
  const registrar =
    text.match(/Registrar:\s*(.*)/i)?.[1] ||
    text.match(/Registrar Name:\s*(.*)/i)?.[1] ||
    "Không rõ";

  const created =
    text.match(/Creation Date:\s*(.*)/i)?.[1] ||
    text.match(/Created On:\s*(.*)/i)?.[1] ||
    "Không rõ";

  const expires =
    text.match(/Registry Expiry Date:\s*(.*)/i)?.[1] ||
    text.match(/Expiry Date:\s*(.*)/i)?.[1] ||
    "Không rõ";

  const status =
    [...text.matchAll(/Status:\s*(.*)/gi)].map(m => m[1]) || [];

  return { registrar, created, expires, status };
}

function getWhois(domain) {
  return new Promise((resolve) => {
    exec(`whois ${domain}`, (err, stdout) => {
      if (err || !stdout) {
        return resolve({
          registrar: "Không rõ",
          created: "Không rõ",
          expires: "Không rõ",
          status: []
        });
      }
      resolve(parseWhois(stdout));
    });
  });
}

/* ============================= */
/* ===== DNS LOOKUP ============ */
/* ============================= */

async function dnsLookup(domain, type) {
  try {
    const result = await dns.resolve(domain, type);
    return result;
  } catch {
    return [];
  }
}

/* ============================= */
/* ===== IP INFO =============== */
/* ============================= */

async function getIPInfo(ip) {
  try {
    const res = await axios.get(`https://ipinfo.io/${ip}/json`);
    return {
      ip: res.data.ip,
      org: res.data.org,
      country: res.data.country,
      region: res.data.region,
      city: res.data.city
    };
  } catch {
    return {};
  }
}

/* ============================= */
/* ===== WEBSITE ANALYSIS ====== */
/* ============================= */

async function analyzeWebsite(domain) {
  try {
    const res = await axios.get(`http://${domain}`, {
      timeout: 8000,
      validateStatus: () => true
    });

    const headers = res.headers;
    const html = res.data || "";
    const $ = cheerio.load(html);

    let tech = [];
    let score = 100;

    const https = headers["strict-transport-security"] ? true : false;
    if (!https) score -= 10;

    const server = headers["server"] || "Unknown";

    if (html.includes("wp-content")) tech.push("WordPress");
    if (html.includes("react")) tech.push("React");
    if (html.includes("vue")) tech.push("Vue");
    if (html.includes("jquery")) tech.push("jQuery");
    if (headers["cf-ray"]) tech.push("Cloudflare");

    if (tech.length === 0) tech.push("Unknown");

    if (!headers["x-frame-options"]) score -= 5;
    if (!headers["content-security-policy"]) score -= 5;
    if (!headers["x-content-type-options"]) score -= 5;

    if (score < 0) score = 0;

    return {
      status: res.status,
      server,
      https,
      technologies: tech,
      score
    };
  } catch {
    return { error: "Không truy cập được website" };
  }
}

/* ============================= */
/* ===== MAIN ROUTE ============ */
/* ============================= */

app.get("/check", async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  /* WHOIS */
  const whois = await getWhois(domain);

  /* DNS */
  const dnsData = {
        A: await dnsLookup(domain, "IPv4 (A)"),
        AAAA: await dnsLookup(domain, "IPv6 (AAAA)"),
        CNAME: await dnsLookup(domain, "CNAME"),
        NS: await dnsLookup(domain, "NS"),
        MX: await dnsLookup(domain, "MX"),
        TXT: await dnsLookup(domain, "TXT"),
        PTR: await dnsLookup(domain, "PTR"),
        SRV: await dnsLookup(domain, "SRV"),
        SOA: await dnsLookup(domain, "SOA"),
        CAA: await dnsLookup(domain, "CAA"),
        DS: await dnsLookup(domain, "DS"),
        DNSKEY: await dnsLookup(domain, "DNSKEY")
  };

  /* IP & ASN */
  let ipInfo = {};
  if (dnsData.A.length > 0) {
    ipInfo = await getIPInfo(dnsData.A[0]);
  }

  /* Website */
  const website = await analyzeWebsite(domain);

  res.json({
    domain,
    whois,
    dns: dnsData,
    ip: ipInfo,
    website
  });
});

/* ============================= */

app.listen(PORT, () => {
  console.log(`WHOIS Support API running on 127.0.0.1:${PORT}`);
});
