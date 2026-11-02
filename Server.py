"""Cryptaude MCP server v1.

One tool: analyze_token(address, chain). Pulls DEX Screener (market),
GoPlus (security) and Etherscan V2 (verification) in parallel and returns
a single verdict with red flags.
"""
import asyncio
import os

import httpx
from mcp.server.fastmcp import FastMCP

PORT = int(os.environ.get("PORT", "8000"))
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

mcp = FastMCP("cryptaude", host="0.0.0.0", port=PORT, stateless_http=True)

REPLY_STYLE = {
    "beginner": (
        "Reply in very simple everyday English, like explaining to a friend who "
        "has never touched crypto. No jargon. If you must use a crypto word, "
        "explain it in one short sentence. Short sentences. Say clearly if it "
        "looks dangerous."
    ),
    "intermediate": (
        "Reply in clear English. Common crypto terms (liquidity, market cap, "
        "tokenomics) are fine, but briefly explain advanced ones."
    ),
    "professional": (
        "Reply in concise, technical language. Use precise on-chain and market "
        "terminology. Lead with numbers and flags, skip basic explanations."
    ),
}

PLAIN = [
    ("honeypot", "You can buy this coin but you will not be able to sell it. Stay away."),
    ("no trading pairs", "Nobody is trading this coin anywhere yet, so you may not be able to sell it."),
    ("low liquidity", "There is very little money in the trading pool, so even a small sale can crash the price."),
    ("very new pair", "This coin only started trading very recently. New coins are where most scams happen."),
    ("high tax", "The coin takes a big cut every time you buy or sell."),
    ("not verified", "The coin's code is hidden, so nobody can check what it really does."),
    ("mint", "The creator can make unlimited new coins, which would make yours worth less."),
    ("hidden owner", "The creator has secret control over the coin."),
    ("paused", "The creator can freeze trading whenever they want."),
    ("top 10 holders", "A few wallets hold most of the coins. If they sell, the price can crash."),
    ("no security data", "Our safety checker has no info on this coin yet, likely because it is brand new."),
]

PLAIN_VERDICT = {
    "HIGH RISK": "Very dangerous. Do not buy.",
    "RISKY": "Many warning signs. Only touch this if you accept losing everything you put in.",
    "CAUTION": "Some warning signs. Be careful and only use money you can afford to lose.",
    "NO MAJOR FLAGS": "No big warning signs found, but that does not mean it is safe.",
}


def _plain_flags(flags: list[str]) -> list[str]:
    out = []
    for f in flags:
        low = f.lower()
        for key, text in PLAIN:
            if key in low:
                out.append(text)
                break
        else:
            out.append(f)
    return list(dict.fromkeys(out))


def _mode(mode: str) -> str:
    mode = (mode or "intermediate").lower().strip()
    return mode if mode in REPLY_STYLE else "intermediate"


@mcp.custom_route("/", methods=["GET"])
async def home(request):
    from starlette.responses import HTMLResponse

    return HTMLResponse(
        "<body style='font-family:sans-serif;background:#0b0f1a;color:#fff;"
        "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
        "<div style='text-align:center'><h1>Cryptaude</h1>"
        "<p>Server is live. Connector endpoint: /mcp</p></div></body>"
    )


@mcp.prompt(name="beginner", description="Cryptaude: explain everything in simple everyday English")
def beginner_prompt() -> str:
    return "From now on in this chat, use Cryptaude in BEGINNER mode (mode='beginner'). " + REPLY_STYLE["beginner"]


@mcp.prompt(name="intermediate", description="Cryptaude: balanced explanations")
def intermediate_prompt() -> str:
    return "From now on in this chat, use Cryptaude in INTERMEDIATE mode (mode='intermediate'). " + REPLY_STYLE["intermediate"]


@mcp.prompt(name="professional", description="Cryptaude: technical, numbers-first")
def professional_prompt() -> str:
    return "From now on in this chat, use Cryptaude in PROFESSIONAL mode (mode='professional'). " + REPLY_STYLE["professional"]


# chain name -> (chain id, DEX Screener chain slug)
CHAINS = {
    "ethereum": (1, "ethereum"),
    "base": (8453, "base"),
    "bsc": (56, "bsc"),
    "arbitrum": (42161, "arbitrum"),
    "polygon": (137, "polygon"),
    "optimism": (10, "optimism"),
}


async def _get(client: httpx.AsyncClient, url: str, params: dict | None = None):
    try:
        r = await client.get(url, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # keep going if one source fails
        return {"_error": str(e)}


def _f(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


@mcp.tool()
async def analyze_token(address: str, chain: str = "base", mode: str = "intermediate") -> dict:
    """Analyze a token contract in one call: market data, liquidity, security
    flags, holder concentration and contract verification, with a risk verdict.

    Args:
        address: Token contract address (0x...).
        chain: ethereum, base, bsc, arbitrum, polygon or optimism.
        mode: beginner, intermediate or professional. Controls how the result
            is explained. Use the mode the user picked earlier in the chat.
    """
    mode = _mode(mode)
    chain = chain.lower().strip()
    if chain not in CHAINS:
        return {"error": f"Unsupported chain. Use one of: {', '.join(CHAINS)}"}
    address = address.strip().lower()
    if not (address.startswith("0x") and len(address) == 42):
        return {"error": "Address must be a 0x... address, 42 characters."}

    chain_id, ds_slug = CHAINS[chain]

    async with httpx.AsyncClient() as client:
        tasks = [
            _get(client, f"https://api.dexscreener.com/latest/dex/tokens/{address}"),
            _get(
                client,
                f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}",
                {"contract_addresses": address},
            ),
        ]
        if ETHERSCAN_KEY:
            tasks.append(
                _get(
                    client,
                    "https://api.etherscan.io/v2/api",
                    {
                        "chainid": chain_id,
                        "module": "contract",
                        "action": "getsourcecode",
                        "address": address,
                        "apikey": ETHERSCAN_KEY,
                    },
                )
            )
        results = await asyncio.gather(*tasks)

    ds, gp = results[0], results[1]
    es = results[2] if len(results) > 2 else None

    flags: list[str] = []
    out: dict = {"address": address, "chain": chain}

    # ---- Market (DEX Screener) ----
    pairs = [p for p in (ds.get("pairs") or []) if p.get("chainId") == ds_slug]
    if pairs:
        pairs.sort(key=lambda p: _f((p.get("liquidity") or {}).get("usd")), reverse=True)
        p = pairs[0]
        liq = _f((p.get("liquidity") or {}).get("usd"))
        out["market"] = {
            "name": (p.get("baseToken") or {}).get("name"),
            "symbol": (p.get("baseToken") or {}).get("symbol"),
            "price_usd": p.get("priceUsd"),
            "liquidity_usd": liq,
            "fdv": p.get("fdv"),
            "market_cap": p.get("marketCap"),
            "volume_24h": (p.get("volume") or {}).get("h24"),
            "price_change": p.get("priceChange"),
            "txns_24h": (p.get("txns") or {}).get("h24"),
            "dex": p.get("dexId"),
            "pair_count": len(pairs),
            "pair_url": p.get("url"),
        }
        if liq < 10_000:
            flags.append(f"Low liquidity (${liq:,.0f})")
        created = p.get("pairCreatedAt")
        if created:
            import time

            age_h = (time.time() * 1000 - created) / 3_600_000
            out["market"]["pair_age_hours"] = round(age_h, 1)
            if age_h < 24:
                flags.append(f"Very new pair ({age_h:.1f}h old)")
    else:
        out["market"] = None
        flags.append("No trading pairs found on DEX Screener")

    # ---- Links (X + explorers) ----
    links: dict = {}
    sym = (out.get("market") or {}).get("symbol")
    links["x_search_contract"] = f"https://x.com/search?q={address}&f=live"
    if sym:
        links["x_search_ticker"] = f"https://x.com/search?q=%24{sym}&f=live"
    if pairs:
        info = pairs[0].get("info") or {}
        for soc in info.get("socials") or []:
            if soc.get("type") == "twitter":
                links["project_x"] = soc.get("url")
            elif soc.get("type") == "telegram":
                links["project_telegram"] = soc.get("url")
        sites = info.get("websites") or []
        if sites:
            links["website"] = sites[0].get("url")
        links["dexscreener"] = pairs[0].get("url")
    out["links"] = links

    # ---- Security (GoPlus) ----
    sec = ((gp.get("result") or {}).get(address)) if isinstance(gp, dict) else None
    if sec:
        holders = sec.get("holders") or []
        top10 = sum(_f(h.get("percent")) for h in holders[:10]) * 100
        out["security"] = {
            "honeypot": sec.get("is_honeypot") == "1",
            "buy_tax_pct": round(_f(sec.get("buy_tax")) * 100, 2),
            "sell_tax_pct": round(_f(sec.get("sell_tax")) * 100, 2),
            "open_source": sec.get("is_open_source") == "1",
            "mintable": sec.get("is_mintable") == "1",
            "proxy": sec.get("is_proxy") == "1",
            "hidden_owner": sec.get("hidden_owner") == "1",
            "can_retake_ownership": sec.get("can_take_back_ownership") == "1",
            "transfer_pausable": sec.get("transfer_pausable") == "1",
            "owner": sec.get("owner_address"),
            "creator": sec.get("creator_address"),
            "holder_count": sec.get("holder_count"),
            "top10_holders_pct": round(top10, 1),
        }
        s = out["security"]
        if s["honeypot"]:
            flags.append("HONEYPOT: sells are blocked")
        if s["buy_tax_pct"] > 10 or s["sell_tax_pct"] > 10:
            flags.append(f"High tax (buy {s['buy_tax_pct']}%, sell {s['sell_tax_pct']}%)")
        if not s["open_source"]:
            flags.append("Contract source not verified")
        if s["mintable"]:
            flags.append("Owner can mint new tokens")
        if s["hidden_owner"] or s["can_retake_ownership"]:
            flags.append("Hidden owner / can retake ownership")
        if s["transfer_pausable"]:
            flags.append("Transfers can be paused")
        if top10 > 50:
            flags.append(f"Top 10 holders own {top10:.0f}% (may include LP/burn)")
    else:
        out["security"] = None
        flags.append("No security data from GoPlus (token may be too new)")

    # ---- Verification (Etherscan V2) ----
    if es is not None:
        res = es.get("result") if isinstance(es, dict) else None
        if isinstance(res, list) and res:
            verified = bool(res[0].get("SourceCode"))
            out["etherscan"] = {
                "verified": verified,
                "contract_name": res[0].get("ContractName"),
                "compiler": res[0].get("CompilerVersion"),
            }
            if not verified:
                flags.append("Etherscan: contract not verified")
        else:
            out["etherscan"] = {"error": "lookup failed"}

    # ---- Verdict ----
    severe = any(
        k in f for f in flags for k in ("HONEYPOT", "No trading pairs", "Hidden owner")
    )
    if severe:
        verdict = "HIGH RISK"
    elif len(flags) >= 3:
        verdict = "RISKY"
    elif flags:
        verdict = "CAUTION"
    else:
        verdict = "NO MAJOR FLAGS"
    out["verdict"] = verdict
    out["red_flags"] = flags
    out["mode"] = mode
    out["reply_style"] = REPLY_STYLE[mode]
    out["note"] = "Automated checks only. Not financial advice. Always DYOR."

    if mode == "beginner":
        m = out.get("market") or {}
        return {
            "token": f"{m.get('name')} ({m.get('symbol')})" if m else address,
            "chain": chain,
            "verdict": verdict,
            "in_plain_english": PLAIN_VERDICT[verdict],
            "warnings": _plain_flags(flags),
            "price_usd": m.get("price_usd"),
            "money_in_trading_pool_usd": m.get("liquidity_usd"),
            "links": links,
            "mode": mode,
            "reply_style": REPLY_STYLE[mode],
            "note": out["note"],
        }
    return out


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
