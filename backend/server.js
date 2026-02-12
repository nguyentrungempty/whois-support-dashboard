const express = require("express");
const cors = require("cors");
const axios = require("axios");
const dns = require("dns").promises;
const https = require("https");
const tls = require("tls");
const cheerio = require("cheerio");
const { exec } = require("child_process");

const app = express();
app.use(cors());
app.use(express.json());

/* ===============================
   RDAP AUTO BY TLD
================================ */
function getRdapUrl(domain) {
  const tld = domain.split(".").pop().toLowerCase();
  const map = {
    com: "https://rdap.verisign.com/com/v1/domain/",
    net: "https://rdap.verisign.com/net/v1/domain/",
    org: "https://rdap.publicinterestregistry.org/rdap/domain/",
    xyz: "https://rdap.nic.xyz/domain/",
    vn: "https://rdap.vnnic.vn/domain/"
  };
  return map[tld] || "https://rdap.org/domain/";
}

async function getWhois(domain) {
  let result = {
    registrar: "Không rõ",
    created: "Không rõ",
    expires: "Không rõ",
    status: []
  };

  try {
    const rdapBase = getRdapUrl(domain);
    const url = rdapBase.endsWith("/")
      ? rdapBase + domain
      : rdapBase + "/" + domain;

    const res = await axios.get(url, { timeout: 5000 });
    const data = res.data;

    if (data.entities) {
      const registrar = data.entities.find(e =>
        e.roles && e.roles.includes("registrar")
      );
      if (registrar?.vcardArray) {
        const fn = registrar.vcardArray[1].find(v => v[0] === "fn");
        if (fn) result.registrar = fn[3];
      }
    }

    if (data.events) {
      data.events.forEach(e => {
        if (e.eventAction === "registration")
          result.created = e.eventDate;
        if (e.eventAction === "expiration")
          result.expires = e.eventDate;
      });
    }

    if (data.status) result.status = data.status;

  } catch {}
  return result;
}

/* ===============================
   DNS
================================ */
async function getDNS(domain) {
  const records = {};
  try { records.A = await dns.resolve4(domain); } catch {}
  try { records.AAAA = await dns.resolve6(domain); } catch {}
  try { records.MX = await dns.resolveMx(domain); } catch {}
  try { records.NS = await dns.resolveNs(domain); } catch {}
  try { records.TXT = await dns.resolveTxt(domain); } catch {}
  try { records.SOA = await dns.resolveSoa(domain); } catch {}
  try { records.SRV = await dns.resolveSrv(domain); } catch {}
  try { records.CAA = await dns.resolveCaa(domain); } catch {}
  return records;
}

/* ===============================
   IP INFO
================================ */
async function getIPInfo(ip) {
  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}`);
    return {
      ip,
      org: res.data.org,
      country: res.data.country,
      region: res.data.regionName,
      city: res.data.city,
      asn: res.data.as
    };
  } catch {
    return { ip };
  }
}

/* ===============================
   SSL CHECK
================================ */
function getSSL(domain) {
  return new Promise(resolve => {
    const socket = tls.connect(443, domain, { servername: domain }, () => {
      const cert = socket.getPeerCertificate();
      resolve({
        issuer: cert.issuer?.O,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to
      });
      socket.end();
    });
    socket.on("error", () => resolve(null));
  });
}

/* ===============================
   WEBSITE CHECK
================================ */
async function getWebsite(domain) {
  try {
    const start = Date.now();
    const res = await axios.get(`https://${domain}`, { timeout: 8000 });
    const time = Date.now() - start;

    const $ = cheerio.load(res.data);

    return {
      title: $("title").text(),
      server: res.headers.server || null,
      poweredBy: res.headers["x-powered-by"] || null,
      responseTime: time,
      https: true
    };
  } catch {
    return null;
  }
}

/* ===============================
   SECURITY CHECK
================================ */
async function getSecurity(domain) {
  try {
    const res = await axios.get(`https://${domain}`, { timeout: 5000 });
    return {
      hsts: !!res.headers["strict-transport-security"],
      xframe: !!res.headers["x-frame-options"],
      xss: !!res.headers["x-xss-protection"],
      contentType: !!res.headers["x-content-type-options"]
    };
  } catch {
    return null;
  }
}

/* ===============================
   MAIN API
================================ */
app.get("/api/check", async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  try {
    const whois = await getWhois(domain);
    const dnsData = await getDNS(domain);

    let ipInfo = null;
    if (dnsData.A?.length > 0)
      ipInfo = await getIPInfo(dnsData.A[0]);

    const ssl = await getSSL(domain);
    const website = await getWebsite(domain);
    const security = await getSecurity(domain);

    res.json({
      domain,
      whois,
      dns: dnsData,
      ipInfo,
      ssl,
      website,
      security
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3001, () =>
  console.log("WHOIS Dashboard API running on 3001")
);
