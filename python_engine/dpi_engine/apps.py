from __future__ import annotations

from .types import AppType


APP_PATTERNS: dict[AppType, tuple[str, ...]] = {
    AppType.YOUTUBE: ("youtube", "ytimg", "youtu.be", "yt3.ggpht"),
    AppType.GOOGLE: ("google", "gstatic", "googleapis", "ggpht", "gvt1"),
    AppType.FACEBOOK: ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"),
    AppType.INSTAGRAM: ("instagram", "cdninstagram"),
    AppType.WHATSAPP: ("whatsapp", "wa.me"),
    AppType.TWITTER: ("twitter", "twimg", "x.com", "t.co"),
    AppType.NETFLIX: ("netflix", "nflxvideo", "nflximg"),
    AppType.AMAZON: ("amazon", "amazonaws", "cloudfront", "aws"),
    AppType.MICROSOFT: ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
    AppType.APPLE: ("apple", "icloud", "mzstatic", "itunes"),
    AppType.TELEGRAM: ("telegram", "t.me"),
    AppType.TIKTOK: ("tiktok", "tiktokcdn", "musical.ly", "bytedance"),
    AppType.SPOTIFY: ("spotify", "scdn.co"),
    AppType.ZOOM: ("zoom",),
    AppType.DISCORD: ("discord", "discordapp"),
    AppType.GITHUB: ("github", "githubusercontent"),
    AppType.CLOUDFLARE: ("cloudflare", "cf-"),
}


def sni_to_app_type(host: str) -> AppType:
    if not host:
        return AppType.UNKNOWN
    lower = host.lower()
    for app_type, needles in APP_PATTERNS.items():
        if any(n in lower for n in needles):
            return app_type
    return AppType.HTTPS
