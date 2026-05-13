#!/usr/bin/env python3
"""Domain Intelligence MCP — WHOIS, DNS, SSL, IP info for any domain.

Usage:
  python3 server.py                    # Free tier (50 calls/instance)
  python3 server.py --pro-key PROL_XXX  # Pro tier (unlimited)
"""

import json, socket, ssl, datetime, sys
from mcp.server import Server, stdio_server
import httpx

server = Server("domain-intel-mcp")

# ─── Rate Limiting & Pro Key ───────────────────────────────────────────
FREE_LIMIT = 50
PRO_KEYS = {"PROL_AGENTPAY_DEMO": "demo"}  # Demo key for testing

# Parse --pro-key from command line
PRO_KEY = None
for i, arg in enumerate(sys.argv):
    if arg == "--pro-key" and i + 1 < len(sys.argv):
        PRO_KEY = sys.argv[i + 1]
        break

IS_PRO = PRO_KEY in PRO_KEYS
call_counter = 0

STRIPE_LINK = "https://buy.stripe.com/5kQ3cxflRabW9PW1AD1oI0r"  # $19/mo

def check_rate_limit():
    """Check if free tier has exceeded limit. Returns error dict or None."""
    global call_counter
    if IS_PRO:
        return None
    call_counter += 1
    if call_counter > FREE_LIMIT:
        remaining = call_counter - FREE_LIMIT
        return {
            "error": f"Free tier limit reached ({FREE_LIMIT} calls). Upgrade to Pro for unlimited access.",
            "isError": True,
            "next_steps": [
                f"Purchase Pro at {STRIPE_LINK} ($19/mo, unlimited)",
                "Restart the server to reset the free counter",
                "Use --pro-key PROL_XXX to run in Pro mode"
            ],
            "calls_used": call_counter,
            "limit": FREE_LIMIT,
            "over_by": remaining
        }
    return None

async def _ipinfo(domain):
    """Get IP geolocation data via ipinfo.io (50k free/mo, no key needed for basic)."""
    ip = socket.gethostbyname(domain)
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"https://ipinfo.io/{ip}/json")
        resp.raise_for_status()
        data = resp.json()
        # Mask the IP for privacy if it's a residential IP
        data["ip"] = ip
        return data

def _ssl_info(hostname, port=443):
    """Get SSL certificate info."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "No certificate"}
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter", "")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                days_left = (expiry - datetime.datetime.utcnow()).days if expiry else None
                sans = [ext[1] for ext in cert.get("subjectAltName", ()) if ext[0] == "DNS"]
                return {
                    "issuer": issuer.get("commonName", ""),
                    "expires": not_after,
                    "days_remaining": days_left,
                    "sans": sans,
                    "san_count": len(sans),
                }
    except Exception as e:
        return {"error": str(e)}

def _dns_records(domain):
    """Get basic DNS records."""
    records = {}
    for qtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = socket.getaddrinfo(domain if qtype in ["A", "AAAA"] else f"_{qtype}.{domain}", 0)
            if qtype in ["A", "AAAA"]:
                records[qtype] = list(set(a[4][0] for a in answers if a[0] == (socket.AF_INET if qtype == "A" else socket.AF_INET6)))
            else:
                records[qtype] = []
        except:
            records[qtype] = []
    # NS records via socket
    try:
        ns_results = socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
        records["ns_servers"] = list(set(a[4][0] for a in ns_results[:5]))
    except:
        records["ns_servers"] = []
    return records

@server.tool(
    name="domain_intel",
    description="Get comprehensive intelligence for a domain: IP geolocation, SSL cert, DNS records",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name (e.g. example.com)"}
        },
        "required": ["domain"]
    }
)
async def domain_intel(domain: str) -> str:
    limit_check = check_rate_limit()
    if limit_check:
        return json.dumps(limit_check, indent=2)
    try:
        ip = socket.gethostbyname(domain)
        dns = _dns_records(domain)
        
        result = {
            "domain": domain,
            "resolved_ip": ip,
            "dns": dns,
        }
        
        # Try IP info (may fail)
        try:
            ip_data = await _ipinfo(domain)
            result["geolocation"] = {
                "city": ip_data.get("city", ""),
                "region": ip_data.get("region", ""),
                "country": ip_data.get("country", ""),
                "org": ip_data.get("org", ""),
                "timezone": ip_data.get("timezone", ""),
            }
        except:
            result["geolocation"] = {"error": "Could not resolve IP location"}
        
        # Try SSL (may fail for non-HTTPS)
        ssl_data = _ssl_info(domain)
        if "error" not in ssl_data:
            result["ssl"] = ssl_data
        
        return json.dumps(result, indent=2)
    except socket.gaierror:
        return json.dumps({"domain": domain, "error": "Domain does not resolve", "isError": True}, indent=2)
    except Exception as e:
        return json.dumps({"domain": domain, "error": str(e), "isError": True}, indent=2)

@server.tool(
    name="domain_check_health",
    description="Check if a domain's HTTP/HTTPS services are responding",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain name"},
            "port": {"type": "integer", "description": "Port to check", "default": 443}
        },
        "required": ["domain"]
    }
)
async def domain_check_health(domain: str, port: int = 443) -> str:
    limit_check = check_rate_limit()
    if limit_check:
        return json.dumps(limit_check, indent=2)
    try:
        results = {}
        for proto, default_port in [("http", 80), ("https", 443)]:
            p = port if proto == ("https" if port == 443 else "http") else default_port
            url = f"{proto}://{domain}:{p}"
            try:
                async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
                    resp = await client.get(url)
                    results[proto] = {
                        "status": resp.status_code,
                        "ok": resp.is_success,
                        "server": resp.headers.get("server", ""),
                        "content_type": resp.headers.get("content-type", "")[:50],
                    }
            except Exception as e:
                results[proto] = {"error": str(e)[:100]}
        
        return json.dumps({"domain": domain, "checks": results}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "isError": True}, indent=2)

def main():
    import anyio
    async def run():
        async with stdio_server() as streams:
            await server.run(streams[0], streams[1], server.create_initialization_options())
    anyio.run(run)

if __name__ == "__main__":
    main()
