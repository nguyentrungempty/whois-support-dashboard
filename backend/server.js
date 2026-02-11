const express = require("express");
const axios = require("axios");
const detectProvider = require("./provider-map");
const cheerio = require("cheerio");
const app = express();

/* ================= HELPERS ================= */

function formatDate(ts) {
    if (!ts) return "Không rõ";
    if (typeof ts === "string") return ts.split("T")[0].split("-").reverse().join("/");
    if (ts.toString().length === 10) {
        return new Date(ts * 1000).toLocaleDateString("vi-VN");
    }
    return "Không rõ";
}

async function dnsLookup(domain, type) {
    try {
        const res = await axios.get(
            "https://dns.google/resolve?name=" + domain + "&type=" + type
        );
        return res.data.Answer ? res.data.Answer.map(r => r.data) : [];
    } catch (e) {
        return [];
    }
}

async function ipLookup(ip) {
    try {
        const res = await axios.get("https://ipinfo.io/" + ip + "/json");
        return {
            ip: ip,
            asn: res.data.org || "Không rõ",
            provider: detectProvider(res.data.org || ""),
            country: res.data.country || "",
            region: res.data.region || "",
            city: res.data.city || ""
        };
    } catch (e) {
        return {
            ip: ip,
            asn: "Không rõ",
            provider: "Unknown"
        };
    }
}

async function analyzeWebsite(domain) {
  try {
    const url = "http://" + domain;
    const res = await axios.get(url, {
      timeout: 8000,
      validateStatus: () => true
    });

    const headers = res.headers;
    const html = res.data || "";
    const $ = cheerio.load(html);

    let tech = [];
    let score = 100;

    // HTTPS check
    const https = headers["strict-transport-security"] ? true : false;
    if (!https) score -= 10;

    // Server header
    const server = headers["server"] || "Unknown";

    // Technology detection
    if (html.includes("wp-content")) tech.push("WordPress");
    if (html.includes("react")) tech.push("React");
    if (html.includes("vue")) tech.push("Vue");
    if (html.includes("jquery")) tech.push("jQuery");
    if (headers["cf-ray"]) tech.push("Cloudflare");

    if (tech.length === 0) tech.push("Unknown");

    // Basic scoring
    if (!headers["x-frame-options"]) score -= 5;
    if (!headers["content-security-policy"]) score -= 5;
    if (!headers["x-content-type-options"]) score -= 5;

    if (score < 0) score = 0;

    return {
      status: res.status,
      server: server,
      technologies: tech,
      https: https,
      score: score
    };

  } catch (e) {
    return {
      error: "Không truy cập được website"
    };
  }
}

async function rdapLookup(domain) {
    try {
        const res = await axios.get(
            "https://rdap.identitydigital.services/rdap/domain/" + domain
        );
        return res.data;
    } catch (e) {
        return null;
    }
}

/* ================= API ================= */

app.get("/check", async function(req, res) {
    const domain = req.query.domain;
    if (!domain) {
        return res.json({ error: "Thiếu domain" });
    }
    /* ---------- WHOIS (RDAP) ---------- */
    const rdap = await rdapLookup(domain);

    let registrar = "Không rõ";
    let created = null;
    let expires = null;
    let status = [];

    if (rdap) {
        status = rdap.status || [];

        if (rdap.entities && Array.isArray(rdap.entities)) {
            for (let i = 0; i < rdap.entities.length; i++) {
                const e = rdap.entities[i];
                if (e.roles && e.roles.indexOf("registrar") !== -1) {
                    if (e.vcardArray && e.vcardArray[1]) {
                        const vc = e.vcardArray[1];
                        for (let j = 0; j < vc.length; j++) {
                            if (vc[j][0] === "fn" && vc[j][3]) {
                                registrar = vc[j][3];
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (rdap.events && Array.isArray(rdap.events)) {
            for (let k = 0; k < rdap.events.length; k++) {
                if (rdap.events[k].eventAction === "registration") {
                    created = rdap.events[k].eventDate;
                }
                if (rdap.events[k].eventAction === "expiration") {
                    expires = rdap.events[k].eventDate;
                }
            }
        }
    }

    const whois = {
        registrar: registrar,
        created: formatDate(created),
        expires: formatDate(expires),
        status: status
    };

    /* ---------- DNS ---------- */
    const dns = {
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

    /* ---------- IP / ASN ---------- */
    const ips = dns.A.concat(dns.AAAA);
    const uniqueIPs = ips.filter((v, i, a) => a.indexOf(v) === i);

    const ipNetworks = [];
    for (let m = 0; m < uniqueIPs.length; m++) {
        ipNetworks.push(await ipLookup(uniqueIPs[m]));
    }

    /* ---------- ALERTS ---------- */
    const alerts = [];

    if (expires) {
        const d = new Date(expires);
        const days = Math.ceil((d - new Date()) / (1000 * 60 * 60 * 24));
        if (days < 30) {
            alerts.push("Domain sắp hết hạn (" + days + " ngày)");
        }
    }

    for (let n = 0; n < ipNetworks.length; n++) {
        if (
            registrar !== "Không rõ" &&
            ipNetworks[n].provider !== "Other" &&
            registrar.toUpperCase().indexOf(ipNetworks[n].provider) === -1
        ) {
            alerts.push(
                "Domain đăng ký tại " + registrar +
                " nhưng IP thuộc " + ipNetworks[n].provider
            );
        }
    }

    const website = await analyzeWebsite(domain);

    res.json({
        domain: domain,
        whois: whois,
        dns: dns,
        ip_networks: ipNetworks,
        alerts: alerts,
        website: website
    });
});

/* ================= START ================= */

app.listen(3001, "127.0.0.1", function() {
    console.log("WHOIS Support API v2 running on 127.0.0.1:3001");
});
