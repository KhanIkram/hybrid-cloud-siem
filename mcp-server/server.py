#!/usr/bin/env python3
"""
MCP Server for AI-Assisted Threat Hunting
Integrates Splunk + VirusTotal + AbuseIPDB for security investigations via Claude Code

Author: Ikram
Version: 2.0
Last Updated: December 2025

Tools:
  - search_splunk: Execute arbitrary SPL queries
  - enrich_ip: VirusTotal + AbuseIPDB IP enrichment
  - enrich_domain: VirusTotal domain lookup
  - enrich_hash: VirusTotal file hash lookup
  - hunt_beacons: C2 beaconing detection via jitter analysis
  - hunt_ioc: Combined IOC search + enrichment
  - hunt_volume_anomaly: Detect unusual data transfer volumes
  - hunt_new_destinations: Find new external destinations
  - get_network_summary: Network activity overview
  - check_pipeline_health: Data ingestion health check
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ============================================================================
# LOGGING SETUP
# ============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", None)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        *([logging.FileHandler(LOG_FILE)] if LOG_FILE else [])
    ]
)

logger = logging.getLogger("threat-hunter")

# ============================================================================
# CONFIGURATION
# ============================================================================

load_dotenv()

# Splunk Configuration
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

# VirusTotal Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# AbuseIPDB Configuration
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Initialize MCP server
server = Server("threat-hunter")

logger.info(f"Initializing MCP Threat Hunter server")
logger.info(f"Splunk: {SPLUNK_HOST}:{SPLUNK_PORT}")
logger.info(f"VirusTotal API: {'configured' if VIRUSTOTAL_API_KEY else 'not configured'}")
logger.info(f"AbuseIPDB API: {'configured' if ABUSEIPDB_API_KEY else 'not configured'}")


# ============================================================================
# SPLUNK CLIENT
# ============================================================================

class SplunkClient:
    """Async client for Splunk REST API."""
    
    def __init__(self):
        self.base_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"
        self.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
        self.verify_ssl = SPLUNK_VERIFY_SSL
    
    async def search(
        self, 
        query: str, 
        earliest: str = "-24h", 
        latest: str = "now",
        max_results: int = 1000
    ) -> dict:
        """Execute a Splunk search and return results."""
        
        logger.info(f"Executing Splunk search: {query[:100]}...")
        
        if not query.strip().startswith("|") and not query.strip().lower().startswith("search"):
            query = f"search {query}"
        
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            create_url = f"{self.base_url}/services/search/jobs"
            create_data = {
                "search": query,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "max_count": max_results
            }
            
            try:
                response = await client.post(
                    create_url, auth=self.auth, data=create_data, timeout=30.0
                )
                response.raise_for_status()
                
                job_data = response.json()
                sid = job_data.get("sid")
                
                if not sid:
                    return {"error": "Failed to create search job", "details": job_data}
                
                # Poll for completion
                status_url = f"{self.base_url}/services/search/jobs/{sid}"
                for attempt in range(60):
                    status_response = await client.get(
                        status_url, auth=self.auth,
                        params={"output_mode": "json"}, timeout=10.0
                    )
                    status_data = status_response.json()
                    dispatch_state = status_data.get("entry", [{}])[0].get("content", {}).get("dispatchState")
                    
                    if dispatch_state == "DONE":
                        break
                    elif dispatch_state == "FAILED":
                        return {"error": "Search job failed", "details": status_data}
                    await asyncio.sleep(1)
                else:
                    return {"error": "Search job timed out after 60 seconds"}
                
                # Get results
                results_url = f"{self.base_url}/services/search/jobs/{sid}/results"
                results_response = await client.get(
                    results_url, auth=self.auth,
                    params={"output_mode": "json", "count": max_results}, timeout=30.0
                )
                results_data = results_response.json()
                results = results_data.get("results", [])
                
                logger.info(f"Search returned {len(results)} results")
                
                return {
                    "success": True,
                    "query": query,
                    "earliest": earliest,
                    "latest": latest,
                    "result_count": len(results),
                    "results": results
                }
                
            except httpx.HTTPStatusError as e:
                return {"error": f"HTTP error: {e.response.status_code}", "details": str(e)}
            except httpx.RequestError as e:
                return {"error": f"Request error: {str(e)}"}
            except Exception as e:
                return {"error": f"Unexpected error: {str(e)}"}


# ============================================================================
# VIRUSTOTAL CLIENT
# ============================================================================

class VirusTotalClient:
    """Async client for VirusTotal API v3."""
    
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
    
    async def lookup_ip(self, ip: str) -> dict:
        """Look up an IP address in VirusTotal."""
        
        if not self.api_key:
            return {"error": "VirusTotal API key not configured", "ip": ip}
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/ip_addresses/{ip}",
                    headers={"x-apikey": self.api_key},
                    timeout=15.0
                )
                
                if response.status_code == 404:
                    return {"success": True, "ip": ip, "found": False}
                if response.status_code == 429:
                    return {"error": "VirusTotal rate limit exceeded", "ip": ip}
                
                response.raise_for_status()
                data = response.json()
                
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "success": True,
                    "source": "virustotal",
                    "ip": ip,
                    "found": True,
                    "country": attributes.get("country", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                    "asn": attributes.get("asn", "Unknown"),
                    "reputation": attributes.get("reputation", 0),
                    "malicious_votes": stats.get("malicious", 0),
                    "suspicious_votes": stats.get("suspicious", 0),
                    "harmless_votes": stats.get("harmless", 0),
                    "total_votes": sum(stats.values()),
                    "verdict": self._get_verdict(stats),
                    "tags": attributes.get("tags", [])
                }
                
            except Exception as e:
                return {"error": str(e), "ip": ip}
    
    async def lookup_domain(self, domain: str) -> dict:
        """Look up a domain in VirusTotal."""
        
        if not self.api_key:
            return {"error": "VirusTotal API key not configured", "domain": domain}
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/domains/{domain}",
                    headers={"x-apikey": self.api_key},
                    timeout=15.0
                )
                
                if response.status_code == 404:
                    return {"success": True, "domain": domain, "found": False}
                if response.status_code == 429:
                    return {"error": "VirusTotal rate limit exceeded", "domain": domain}
                
                response.raise_for_status()
                data = response.json()
                
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "success": True,
                    "source": "virustotal",
                    "domain": domain,
                    "found": True,
                    "reputation": attributes.get("reputation", 0),
                    "malicious_votes": stats.get("malicious", 0),
                    "categories": attributes.get("categories", {}),
                    "registrar": attributes.get("registrar", "Unknown"),
                    "verdict": self._get_verdict(stats)
                }
                
            except Exception as e:
                return {"error": str(e), "domain": domain}
    
    async def lookup_hash(self, file_hash: str) -> dict:
        """Look up a file hash in VirusTotal."""
        
        if not self.api_key:
            return {"error": "VirusTotal API key not configured", "hash": file_hash}
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers={"x-apikey": self.api_key},
                    timeout=15.0
                )
                
                if response.status_code == 404:
                    return {"success": True, "hash": file_hash, "found": False}
                if response.status_code == 429:
                    return {"error": "VirusTotal rate limit exceeded", "hash": file_hash}
                
                response.raise_for_status()
                data = response.json()
                
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "success": True,
                    "source": "virustotal",
                    "hash": file_hash,
                    "found": True,
                    "file_type": attributes.get("type_description", "Unknown"),
                    "file_size": attributes.get("size", 0),
                    "file_names": attributes.get("names", [])[:5],
                    "malicious_detections": stats.get("malicious", 0),
                    "total_engines": sum(stats.values()),
                    "verdict": self._get_verdict(stats),
                    "tags": attributes.get("tags", [])
                }
                
            except Exception as e:
                return {"error": str(e), "hash": file_hash}
    
    def _get_verdict(self, stats: dict) -> str:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious >= 5:
            return "MALICIOUS"
        elif malicious >= 1 or suspicious >= 3:
            return "SUSPICIOUS"
        return "CLEAN"


# ============================================================================
# ABUSEIPDB CLIENT
# ============================================================================

class AbuseIPDBClient:
    """Async client for AbuseIPDB API v2."""
    
    def __init__(self):
        self.api_key = ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """Check an IP address against AbuseIPDB."""
        
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured", "ip": ip}
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.base_url}/check",
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
                    timeout=15.0
                )
                
                if response.status_code == 429:
                    return {"error": "AbuseIPDB rate limit exceeded", "ip": ip}
                
                response.raise_for_status()
                data = response.json()
                abuse_data = data.get("data", {})
                
                score = abuse_data.get("abuseConfidenceScore", 0)
                if score >= 75:
                    verdict = "MALICIOUS"
                elif score >= 25:
                    verdict = "SUSPICIOUS"
                else:
                    verdict = "CLEAN"
                
                return {
                    "success": True,
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "country_code": abuse_data.get("countryCode", "Unknown"),
                    "isp": abuse_data.get("isp", "Unknown"),
                    "domain": abuse_data.get("domain", "Unknown"),
                    "usage_type": abuse_data.get("usageType", "Unknown"),
                    "total_reports": abuse_data.get("totalReports", 0),
                    "num_distinct_users": abuse_data.get("numDistinctUsers", 0),
                    "last_reported_at": abuse_data.get("lastReportedAt", None),
                    "is_whitelisted": abuse_data.get("isWhitelisted", False),
                    "verdict": verdict
                }
                
            except Exception as e:
                return {"error": str(e), "ip": ip}


# ============================================================================
# INITIALIZE CLIENTS
# ============================================================================

splunk_client = SplunkClient()
vt_client = VirusTotalClient()
abuseipdb_client = AbuseIPDBClient()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def enrich_ip_all_sources(ip: str) -> dict:
    """Enrich IP using all available sources (VT + AbuseIPDB)."""
    
    vt_result, abuse_result = await asyncio.gather(
        vt_client.lookup_ip(ip),
        abuseipdb_client.check_ip(ip),
        return_exceptions=True
    )
    
    if isinstance(vt_result, Exception):
        vt_result = {"error": str(vt_result)}
    if isinstance(abuse_result, Exception):
        abuse_result = {"error": str(abuse_result)}
    
    verdicts = []
    if vt_result.get("verdict"):
        verdicts.append(("VirusTotal", vt_result["verdict"]))
    if abuse_result.get("verdict"):
        verdicts.append(("AbuseIPDB", abuse_result["verdict"]))
    
    if any(v[1] == "MALICIOUS" for v in verdicts):
        overall = "MALICIOUS"
    elif any(v[1] == "SUSPICIOUS" for v in verdicts):
        overall = "SUSPICIOUS"
    else:
        overall = "CLEAN"
    
    return {
        "ip": ip,
        "overall_verdict": overall,
        "verdicts": {source: verdict for source, verdict in verdicts},
        "virustotal": vt_result,
        "abuseipdb": abuse_result
    }


# ============================================================================
# MCP TOOLS
# ============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="search_splunk",
            description="Execute a Splunk SPL query and return results. Use for threat hunting, log analysis, and security investigations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Splunk SPL query to execute"},
                    "earliest": {"type": "string", "description": "Start time (e.g., '-24h', '-7d')", "default": "-24h"},
                    "latest": {"type": "string", "description": "End time (e.g., 'now', '-1h')", "default": "now"},
                    "max_results": {"type": "integer", "description": "Maximum results to return", "default": 100}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="enrich_ip",
            description="Enrich an IP with threat intel from VirusTotal AND AbuseIPDB. Returns reputation, abuse score, ASN, country, and combined verdict.",
            inputSchema={
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to look up"}},
                "required": ["ip"]
            }
        ),
        Tool(
            name="enrich_domain",
            description="Enrich a domain with VirusTotal threat intelligence.",
            inputSchema={
                "type": "object",
                "properties": {"domain": {"type": "string", "description": "Domain name to look up"}},
                "required": ["domain"]
            }
        ),
        Tool(
            name="enrich_hash",
            description="Enrich a file hash (MD5, SHA1, SHA256) with VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {"hash": {"type": "string", "description": "File hash to look up"}},
                "required": ["hash"]
            }
        ),
        Tool(
            name="hunt_beacons",
            description="Hunt for C2 beaconing using jitter analysis. Low jitter (<25%) = automated behavior. 0% jitter = perfect timing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Hours to search back", "default": 24},
                    "jitter_threshold": {"type": "number", "description": "Max jitter % to flag", "default": 25},
                    "min_beacons": {"type": "integer", "description": "Min connections to consider", "default": 10}
                }
            }
        ),
        Tool(
            name="hunt_volume_anomaly",
            description="Hunt for unusual data transfer volumes using z-score analysis. Detects potential exfiltration.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Hours to analyze", "default": 24},
                    "zscore_threshold": {"type": "number", "description": "Z-score threshold (default 2.0)", "default": 2.0}
                }
            }
        ),
        Tool(
            name="hunt_new_destinations",
            description="Find new external destinations that internal hosts connected to recently.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {"type": "integer", "description": "Total hours to search", "default": 24},
                    "new_within_hours": {"type": "integer", "description": "Flag if first seen within X hours", "default": 4}
                }
            }
        ),
        Tool(
            name="hunt_ioc",
            description="Hunt for an IOC across Splunk and enrich with threat intelligence.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "IOC to hunt (IP, domain, or hash)"},
                    "ioc_type": {"type": "string", "description": "Type of IOC", "enum": ["ip", "domain", "hash"]},
                    "hours": {"type": "integer", "description": "Hours to search back", "default": 24}
                },
                "required": ["ioc", "ioc_type"]
            }
        ),
        Tool(
            name="get_network_summary",
            description="Get network activity summary: top talkers, destinations, and ports.",
            inputSchema={
                "type": "object",
                "properties": {"hours": {"type": "integer", "description": "Hours to summarize", "default": 24}}
            }
        ),
        Tool(
            name="check_pipeline_health",
            description="Check data ingestion pipeline health. Returns time since last event per index.",
            inputSchema={"type": "object", "properties": {}}
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool and return results."""
    
    logger.info(f"Tool called: {name}")
    
    try:
        if name == "search_splunk":
            result = await splunk_client.search(
                query=arguments["query"],
                earliest=arguments.get("earliest", "-24h"),
                latest=arguments.get("latest", "now"),
                max_results=arguments.get("max_results", 100)
            )
        
        elif name == "enrich_ip":
            result = await enrich_ip_all_sources(arguments["ip"])
        
        elif name == "enrich_domain":
            result = await vt_client.lookup_domain(arguments["domain"])
        
        elif name == "enrich_hash":
            result = await vt_client.lookup_hash(arguments["hash"])
        
        elif name == "hunt_beacons":
            hours = arguments.get("hours", 24)
            jitter = arguments.get("jitter_threshold", 25)
            min_beacons = arguments.get("min_beacons", 10)
            
            query = f"""index=netflow earliest=-{hours}h
| search src4_addr=192.168.* NOT (dst4_addr=192.168.* OR dst4_addr=10.*)
| sort 0 src4_addr, dst4_addr, dst_port, _time
| streamstats current=f window=1 last(_time) as prev_time by src4_addr, dst4_addr, dst_port
| eval interval = _time - prev_time
| where interval > 0 AND interval < 7200
| stats count as beacon_count, avg(interval) as avg_interval, stdev(interval) as stdev_interval, sum(in_bytes) as total_bytes by src4_addr, dst4_addr, dst_port
| where beacon_count >= {min_beacons}
| eval jitter_pct = round((stdev_interval / avg_interval) * 100, 1)
| eval avg_interval_sec = round(avg_interval, 1)
| eval total_MB = round(total_bytes/1024/1024, 2)
| where jitter_pct < {jitter}
| table src4_addr, dst4_addr, dst_port, beacon_count, avg_interval_sec, jitter_pct, total_MB
| sort jitter_pct"""
            
            result = await splunk_client.search(query, f"-{hours}h", "now", 100)
            if result.get("success"):
                result["analysis"] = {
                    "description": "C2 beaconing detection via jitter analysis",
                    "methodology": f"Jitter = stdev/avg interval. Threshold: <{jitter}%",
                    "interpretation": {"0%": "Perfect timing", "1-10%": "Very low - likely automated", "10-25%": "Worth investigating"},
                    "next_steps": "Enrich suspicious destination IPs with enrich_ip"
                }
        
        elif name == "hunt_volume_anomaly":
            hours = arguments.get("hours", 24)
            zscore_threshold = arguments.get("zscore_threshold", 2.0)
            
            query = f"""index=netflow earliest=-{hours}h
| search src4_addr=192.168.* NOT (dst4_addr=192.168.* OR dst4_addr=10.*)
| bin _time span=1h
| stats sum(in_bytes) as hourly_bytes by _time, src4_addr
| eventstats avg(hourly_bytes) as avg_bytes, stdev(hourly_bytes) as stdev_bytes by src4_addr
| where stdev_bytes > 0
| eval zscore = round((hourly_bytes - avg_bytes) / stdev_bytes, 2)
| where zscore > {zscore_threshold}
| eval MB = round(hourly_bytes/1024/1024, 2)
| eval avg_MB = round(avg_bytes/1024/1024, 2)
| eval hour = strftime(_time, "%Y-%m-%d %H:%M")
| table hour, src4_addr, MB, avg_MB, zscore
| sort -zscore"""
            
            result = await splunk_client.search(query, f"-{hours}h", "now", 100)
            if result.get("success"):
                result["analysis"] = {
                    "description": "Volume anomaly detection using z-score",
                    "mitre_mapping": "T1041 - Exfiltration Over C2 Channel"
                }
        
        elif name == "hunt_new_destinations":
            hours = arguments.get("hours", 24)
            new_within = arguments.get("new_within_hours", 4)
            
            query = f"""index=netflow earliest=-{hours}h
| search src4_addr=192.168.* NOT (dst4_addr=192.168.* OR dst4_addr=10.*)
| stats earliest(_time) as first_seen, count as flows, sum(in_bytes) as bytes by dst4_addr
| where first_seen > relative_time(now(), "-{new_within}h")
| eval first_seen_time = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval MB = round(bytes/1024/1024, 2)
| sort -first_seen
| table dst4_addr, first_seen_time, flows, MB
| head 20"""
            
            result = await splunk_client.search(query, f"-{hours}h", "now", 100)
            if result.get("success"):
                result["analysis"] = {
                    "description": f"New external destinations (first seen in last {new_within}h)",
                    "mitre_mapping": "T1071 - Application Layer Protocol"
                }
        
        elif name == "hunt_ioc":
            ioc = arguments["ioc"]
            ioc_type = arguments["ioc_type"]
            hours = arguments.get("hours", 24)
            
            if ioc_type == "ip":
                query = f"""index=netflow earliest=-{hours}h
| search src4_addr="{ioc}" OR dst4_addr="{ioc}"
| stats count as flows, sum(in_bytes) as bytes, dc(dst_port) as unique_ports, earliest(_time) as first_seen, latest(_time) as last_seen by src4_addr, dst4_addr
| eval MB = round(bytes/1024/1024, 2)
| eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")"""
                
                splunk_result = await splunk_client.search(query, f"-{hours}h", "now", 100)
                enrichment = await enrich_ip_all_sources(ioc)
                
                result = {
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "splunk_findings": splunk_result,
                    "threat_intelligence": enrichment,
                    "summary": {
                        "found_in_logs": splunk_result.get("result_count", 0) > 0,
                        "overall_verdict": enrichment.get("overall_verdict", "UNKNOWN")
                    }
                }
            elif ioc_type == "domain":
                query = f"""index=syslog earliest=-{hours}h "{ioc}" | stats count as hits"""
                splunk_result = await splunk_client.search(query, f"-{hours}h", "now", 100)
                enrichment = await vt_client.lookup_domain(ioc)
                result = {"ioc": ioc, "ioc_type": ioc_type, "splunk_findings": splunk_result, "threat_intelligence": enrichment}
            elif ioc_type == "hash":
                query = f"""index=* earliest=-{hours}h "{ioc}" | stats count as hits by index"""
                splunk_result = await splunk_client.search(query, f"-{hours}h", "now", 100)
                enrichment = await vt_client.lookup_hash(ioc)
                result = {"ioc": ioc, "ioc_type": ioc_type, "splunk_findings": splunk_result, "threat_intelligence": enrichment}
            else:
                result = {"error": f"Unknown IOC type: {ioc_type}"}
        
        elif name == "get_network_summary":
            hours = arguments.get("hours", 24)
            
            hosts_query = f"""index=netflow earliest=-{hours}h
| search src4_addr=192.168.* OR src4_addr=10.*
| stats dc(dst4_addr) as unique_destinations, sum(in_bytes) as bytes, count as flows by src4_addr
| eval MB = round(bytes/1024/1024, 2) | sort -flows | head 10"""
            
            dest_query = f"""index=netflow earliest=-{hours}h
| search src4_addr=192.168.* NOT (dst4_addr=192.168.* OR dst4_addr=10.*)
| stats count as flows, sum(in_bytes) as bytes by dst4_addr
| eval MB = round(bytes/1024/1024, 2) | sort -bytes | head 10"""
            
            ports_query = f"""index=netflow earliest=-{hours}h
| stats count as flows by dst_port | sort -flows | head 10"""
            
            hosts_result, dest_result, ports_result = await asyncio.gather(
                splunk_client.search(hosts_query, f"-{hours}h", "now", 10),
                splunk_client.search(dest_query, f"-{hours}h", "now", 10),
                splunk_client.search(ports_query, f"-{hours}h", "now", 10)
            )
            
            result = {
                "summary_period": f"Last {hours} hours",
                "generated_at": datetime.now().isoformat(),
                "top_internal_hosts": hosts_result.get("results", []),
                "top_external_destinations": dest_result.get("results", []),
                "top_destination_ports": ports_result.get("results", [])
            }
        
        elif name == "check_pipeline_health":
            query = """| tstats latest(_time) as last_event WHERE index=syslog OR index=netflow by index
| eval minutes_ago = round((now() - last_event) / 60, 1)
| eval status = case(minutes_ago < 15, "HEALTHY", minutes_ago < 30, "WARNING", 1=1, "CRITICAL")
| eval last_event_time = strftime(last_event, "%Y-%m-%d %H:%M:%S")
| table index, last_event_time, minutes_ago, status"""
            
            result = await splunk_client.search(query, "-60m", "now", 10)
            if result.get("success") and result.get("results"):
                statuses = [r.get("status") for r in result["results"]]
                if all(s == "HEALTHY" for s in statuses):
                    overall = "ALL PIPELINES HEALTHY"
                elif any(s == "CRITICAL" for s in statuses):
                    overall = "CRITICAL - DATA MISSING"
                else:
                    overall = "WARNING - CHECK PIPELINES"
                result["overall_status"] = overall
        
        else:
            result = {"error": f"Unknown tool: {name}"}
            
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        result = {"error": str(e), "tool": name}
    
    return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


# ============================================================================
# MAIN
# ============================================================================

async def main():
    """Run the MCP server."""
    logger.info("Starting MCP Threat Hunter server...")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
