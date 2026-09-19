#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <vector>
#include <string>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Map SNI/domain to application type
// ============================================================================
// Hostname matching helpers
//
// A hostname is a structured identifier: dot-separated labels, with ownership
// attached to the suffix. Matching it with a bare substring search ignores that
// structure and produces false positives across label boundaries -- a plain
// find("t.co") reports "www.microsoft.com" as Twitter, because "microsof|t.co|m"
// contains the pattern. Every matcher below respects a label boundary.
// ============================================================================

namespace {

// Split a hostname into its dot-separated labels, ignoring a trailing dot.
std::vector<std::string> splitLabels(const std::string& host) {
    std::vector<std::string> labels;
    std::string current;
    for (char c : host) {
        if (c == '.') {
            if (!current.empty()) labels.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) labels.push_back(current);
    return labels;
}

// True when `host` is exactly `domain`, or is a subdomain of it.
// domainIs("www.microsoft.com", "t.co") is false; domainIs("mobile.t.co", "t.co") is true.
bool domainIs(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    if (host.size() <= domain.size()) return false;
    const size_t offset = host.size() - domain.size();
    return host[offset - 1] == '.' && host.compare(offset, domain.size(), domain) == 0;
}

// True when any single label equals `label` exactly.
// Use for short tokens that would otherwise match inside a longer word:
// labelIs(host, "bing") does not fire on "climbing.example.com".
bool labelIs(const std::vector<std::string>& labels, const std::string& label) {
    for (const auto& l : labels) {
        if (l == label) return true;
    }
    return false;
}

// True when any single label contains `fragment`. Reserved for fragments long
// and distinctive enough that an accidental containment is implausible
// ("microsoft", "cloudfront"); never for short ones.
bool labelHas(const std::vector<std::string>& labels, const std::string& fragment) {
    for (const auto& l : labels) {
        if (l.find(fragment) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

// Map SNI/domain to application type.
//
// Ordering matters: this is a first-match chain, so a vendor whose patterns are
// a subset of another's must be tested first. YouTube is checked before Google
// for exactly that reason -- "yt3.ggpht.com" is a Google-owned domain, and a
// Google rule matching "ggpht" first would make the YouTube rule unreachable.
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    std::string host = sni;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Strip a trailing dot from a fully-qualified name.
    if (!host.empty() && host.back() == '.') host.pop_back();

    const std::vector<std::string> labels = splitLabels(host);

    // YouTube -- must precede Google; see the note above.
    if (labelHas(labels, "youtube") ||
        labelHas(labels, "ytimg") ||
        domainIs(host, "youtu.be") ||
        domainIs(host, "yt3.ggpht.com")) {
        return AppType::YOUTUBE;
    }

    // Google
    if (labelHas(labels, "google") ||
        domainIs(host, "gstatic.com") ||
        domainIs(host, "ggpht.com") ||
        domainIs(host, "gvt1.com")) {
        return AppType::GOOGLE;
    }

    // Instagram -- precedes Facebook/Meta so Meta CDN labels do not absorb it.
    if (labelHas(labels, "instagram")) {
        return AppType::INSTAGRAM;
    }

    // WhatsApp
    if (labelHas(labels, "whatsapp") ||
        domainIs(host, "wa.me")) {
        return AppType::WHATSAPP;
    }

    // Facebook/Meta
    if (labelHas(labels, "facebook") ||
        labelHas(labels, "fbcdn") ||
        labelHas(labels, "fbsbx") ||
        domainIs(host, "fb.com") ||
        domainIs(host, "meta.com")) {
        return AppType::FACEBOOK;
    }

    // Twitter/X -- "x.com" and "t.co" are short enough that only a suffix match
    // is safe; a substring test claims linux.com and microsoft.com respectively.
    if (labelHas(labels, "twitter") ||
        labelHas(labels, "twimg") ||
        domainIs(host, "x.com") ||
        domainIs(host, "t.co")) {
        return AppType::TWITTER;
    }

    // Netflix
    if (labelHas(labels, "netflix") ||
        labelHas(labels, "nflxvideo") ||
        labelHas(labels, "nflximg")) {
        return AppType::NETFLIX;
    }

    // Amazon -- "amazon" also covers amazonaws; bare "aws" is matched as a whole
    // label only, so it does not claim hosts like "lawson.com".
    if (labelHas(labels, "amazon") ||
        labelHas(labels, "cloudfront") ||
        labelIs(labels, "aws")) {
        return AppType::AMAZON;
    }

    // Microsoft -- "bing" is an exact label match; as a fragment it would claim
    // "climbing", "tubing" and similar.
    if (labelHas(labels, "microsoft") ||
        labelHas(labels, "office") ||
        labelHas(labels, "azure") ||
        labelHas(labels, "outlook") ||
        labelIs(labels, "bing") ||
        domainIs(host, "msn.com") ||
        domainIs(host, "live.com")) {
        return AppType::MICROSOFT;
    }

    // Apple
    if (labelHas(labels, "apple") ||
        labelHas(labels, "icloud") ||
        labelHas(labels, "mzstatic") ||
        labelHas(labels, "itunes")) {
        return AppType::APPLE;
    }

    // Telegram -- "t.me" as a suffix only; as a substring it claims
    // "contact.medium.com".
    if (labelHas(labels, "telegram") ||
        domainIs(host, "t.me")) {
        return AppType::TELEGRAM;
    }

    // TikTok
    if (labelHas(labels, "tiktok") ||
        labelHas(labels, "bytedance") ||
        domainIs(host, "musical.ly")) {
        return AppType::TIKTOK;
    }

    // Spotify
    if (labelHas(labels, "spotify") ||
        domainIs(host, "scdn.co")) {
        return AppType::SPOTIFY;
    }

    // Zoom
    if (labelHas(labels, "zoom")) {
        return AppType::ZOOM;
    }

    // Discord -- "discord" also covers discordapp.
    if (labelHas(labels, "discord")) {
        return AppType::DISCORD;
    }

    // GitHub -- "github" also covers githubusercontent.
    if (labelHas(labels, "github")) {
        return AppType::GITHUB;
    }

    // Cloudflare
    if (labelHas(labels, "cloudflare") ||
        labelIs(labels, "cf")) {
        return AppType::CLOUDFLARE;
    }

    // SNI present but not recognised: still known to be TLS.
    return AppType::HTTPS;
}

} // namespace DPI
