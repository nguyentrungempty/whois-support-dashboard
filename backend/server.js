const express = require("express");
const axios = require("axios");
const detectProvider = require("./provider-map");

const app = express();

/* ===== Helpers ===== */

function formatDate(ts) {
    if (!ts) return "Không rõ";
    if (ts.toString().length === 10) {
        return new Date(ts * 1000).toLocaleDateString("vi-VN");
    }
    return ts;
}

async function dnsLookup(domain, type) {
    try {
        const res = await axios.get(
            `https://dns.google/resolve?name=${domain}&type=${type}`
        );
        return res.data.Answer ? res.data.Answer.map(r => r.data) : [];
    } catch {
        return [];
    }
}

async function ipLookup(ip) {
    try {
        const res = await axios.get(`https://ipinfo.io/${ip}/json`);
        return {
            ip,
            asn: res.data.org || "Không rõ",
            provider: detectProvider(res.data.org),
            country: res.data.country,
            region: res.data.region,
            city: res.data.city
        };
    } catch {
        return { ip, asn: "Không rõ", provider: "Unknown" };
    }
}

async function rdapLookup(domain) {
    try {
        const res = await axios.get(
            `https://rdap.identitydigital.services/rdap/domain/${domain}`
        );
        return res.data;
    } catch {
        return null;
    }
}

/* ===== API ===== */

app.get("/check", async(req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.json({ error: "Thiếu domain" });

    // WHOIS (RDAP)
    const rdap = await rdapLookup(domain);
    const whois = rdap ?
        {
            registrar: rdap.entities ? .find(e => e.roles ? .includes("registrar")) ?
                .vcardArray ? .[1] ? .find(i => i[0] === "fn") ? .[3] || "Không rõ",
            created: formatDate(
                rdap.events ? .find(e => e.eventAction === "registration") ? .eventDate
            ),
            expires: formatDate(
                rdap.events ? .find(e => e.eventAction === "expiration") ? .eventDate
            ),
            status: rdap.status || []
        } :
        {
            registrar: "Không rõ",
            created: "Không rõ",
            expires: "Không rõ",
            status: []
        };

    // DNS records
    const dns = {
        A: await dnsLookup(domain, "A"),
        AAAA: await dnsLookup(domain, "AAAA"),
        NS: await dnsLookup(domain, "NS"),
        MX: await dnsLookup(domain, "MX"),
        TXT: await dnsLookup(domain, "TXT"),
        CNAME: await dnsLookup(domain, "CNAME")
    };

    // IP → ASN
    const uniqueIPs = [...new Set([...dns.A, ...dns.AAAA])];
    const ipNetworks = [];
    for (const ip of uniqueIPs) {
        ipNetworks.push(await ipLookup(ip));
    }

    // Alerts
    const alerts = [];

    if (whois.expires !== "Không rõ") {
        const d = new Date(whois.expires.split("/").reverse().join("-"));
        const days = Math.ceil((d - new Date()) / (1000 * 60 * 60 * 24));
        if (days < 30) alerts.push(`Domain sắp hết hạn (${days} ngày)`);
    }

    ipNetworks.forEach(ip => {
        if (
            whois.registrar !== "Không rõ" &&
            ip.provider !== "Other" &&
            !whois.registrar.toUpperCase().includes(ip.provider)
        ) {
            alerts.push(
                `Domain đăng ký tại ${whois.registrar} nhưng IP thuộc ${ip.provider}`
            );
        }
    });

    res.json({
        domain,
        whois,
        dns,
        ip_networks: ipNetworks,
        alerts
    });
});

app.listen(3000, "127.0.0.1", () => {
    console.log("WHOIS Support API running on 127.0.0.1:3000");
});