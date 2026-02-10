function detectProvider(asn = "") {
    const v = asn.toUpperCase();

    if (v.includes("INET")) return "INET";
    if (v.includes("VNPT")) return "VNPT";
    if (v.includes("VIETTEL")) return "Viettel";
    if (v.includes("FPT")) return "FPT";
    if (v.includes("CLOUDFLARE")) return "Cloudflare";
    if (v.includes("AMAZON")) return "AWS";
    if (v.includes("GOOGLE")) return "Google";
    if (v.includes("MICROSOFT")) return "Azure";

    return "Other";
}

module.exports = detectProvider;