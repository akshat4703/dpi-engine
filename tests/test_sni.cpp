#include "types.h"
#include <iostream>
#include <vector>
#include <string>
using namespace DPI;
int main() {
    struct Case { const char* host; AppType want; };
    std::vector<Case> cases = {
        // Regressions: the false positives the substring matcher produced.
        {"www.microsoft.com",       AppType::MICROSOFT},   // contained "t.co"
        {"linux.com",               AppType::HTTPS},       // contained "x.com"
        {"lawson.com",              AppType::HTTPS},       // contained "aws"
        {"contact.medium.com",      AppType::HTTPS},       // contained "t.me"
        {"climbing.example.com",    AppType::HTTPS},       // contained "bing"
        {"soft.contoso.com",        AppType::HTTPS},       // contained "t.co"
        // Previously-dead rule: must now reach YouTube, not Google.
        {"yt3.ggpht.com",           AppType::YOUTUBE},
        // Every listed pattern must reach the rule that lists it.
        {"www.youtube.com",         AppType::YOUTUBE},
        {"i.ytimg.com",             AppType::YOUTUBE},
        {"youtu.be",                AppType::YOUTUBE},
        {"www.google.com",          AppType::GOOGLE},
        {"ssl.gstatic.com",         AppType::GOOGLE},
        {"lh3.ggpht.com",           AppType::GOOGLE},
        {"r1.gvt1.com",             AppType::GOOGLE},
        {"www.instagram.com",       AppType::INSTAGRAM},
        {"scontent.cdninstagram.com", AppType::INSTAGRAM},
        {"web.whatsapp.com",        AppType::WHATSAPP},
        {"wa.me",                   AppType::WHATSAPP},
        {"www.facebook.com",        AppType::FACEBOOK},
        {"scontent.fbcdn.net",      AppType::FACEBOOK},
        {"attachment.fbsbx.com",    AppType::FACEBOOK},
        {"fb.com",                  AppType::FACEBOOK},
        {"about.meta.com",          AppType::FACEBOOK},
        {"twitter.com",             AppType::TWITTER},
        {"pbs.twimg.com",           AppType::TWITTER},
        {"x.com",                   AppType::TWITTER},
        {"t.co",                    AppType::TWITTER},
        {"mobile.t.co",             AppType::TWITTER},
        {"www.netflix.com",         AppType::NETFLIX},
        {"ipv4.nflxvideo.net",      AppType::NETFLIX},
        {"www.amazon.com",          AppType::AMAZON},
        {"s3.amazonaws.com",        AppType::AMAZON},
        {"d1.cloudfront.net",       AppType::AMAZON},
        {"aws.example.com",         AppType::AMAZON},
        {"outlook.office.com",      AppType::MICROSOFT},
        {"blob.core.azure.com",     AppType::MICROSOFT},
        {"www.msn.com",             AppType::MICROSOFT},
        {"login.live.com",          AppType::MICROSOFT},
        {"www.bing.com",            AppType::MICROSOFT},
        {"www.apple.com",           AppType::APPLE},
        {"p01.icloud.com",          AppType::APPLE},
        {"is1.mzstatic.com",        AppType::APPLE},
        {"web.telegram.org",        AppType::TELEGRAM},
        {"t.me",                    AppType::TELEGRAM},
        {"www.tiktok.com",          AppType::TIKTOK},
        {"v16.tiktokcdn.com",       AppType::TIKTOK},
        {"musical.ly",              AppType::TIKTOK},
        {"open.spotify.com",        AppType::SPOTIFY},
        {"i.scdn.co",               AppType::SPOTIFY},
        {"zoom.us",                 AppType::ZOOM},
        {"discord.com",             AppType::DISCORD},
        {"cdn.discordapp.com",      AppType::DISCORD},
        {"github.com",              AppType::GITHUB},
        {"raw.githubusercontent.com", AppType::GITHUB},
        {"www.cloudflare.com",      AppType::CLOUDFLARE},
        // Case and trailing-dot handling.
        {"WWW.YouTube.COM",         AppType::YOUTUBE},
        {"www.github.com.",         AppType::GITHUB},
        {"",                        AppType::UNKNOWN},
        {"example.com",             AppType::HTTPS},
    };
    int fail = 0;
    for (const auto& c : cases) {
        AppType got = sniToAppType(c.host);
        if (got != c.want) {
            std::cout << "FAIL  " << c.host << "  want=" << appTypeToString(c.want)
                      << "  got=" << appTypeToString(got) << "\n";
            ++fail;
        }
    }
    std::cout << (cases.size() - fail) << "/" << cases.size() << " passed\n";
    return fail ? 1 : 0;
}
