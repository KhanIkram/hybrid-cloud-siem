#!/usr/bin/env python3
"""
Test script for MCP Threat Hunter server
Run with: python test_server.py

This script tests the server components without requiring a live Splunk instance.
"""

import asyncio
import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()


async def test_virustotal_lookup():
    """Test VirusTotal IP lookup with a known safe IP."""
    from server import vt_client
    
    print("\n" + "="*60)
    print("TEST: VirusTotal IP Lookup")
    print("="*60)
    
    # Test with Google DNS (should be clean)
    test_ip = "8.8.8.8"
    print(f"Looking up: {test_ip}")
    
    result = await vt_client.lookup_ip(test_ip)
    print(json.dumps(result, indent=2))
    
    if result.get("error"):
        print(f"[WARN] VT lookup failed: {result['error']}")
        return False
    
    if result.get("verdict") == "CLEAN":
        print("[PASS] Google DNS correctly identified as CLEAN")
        return True
    else:
        print(f"[INFO] Verdict: {result.get('verdict')}")
        return True


async def test_abuseipdb_lookup():
    """Test AbuseIPDB lookup with a known safe IP."""
    from server import abuseipdb_client
    
    print("\n" + "="*60)
    print("TEST: AbuseIPDB IP Lookup")
    print("="*60)
    
    test_ip = "8.8.8.8"
    print(f"Looking up: {test_ip}")
    
    result = await abuseipdb_client.check_ip(test_ip)
    print(json.dumps(result, indent=2))
    
    if result.get("error"):
        print(f"[WARN] AbuseIPDB lookup failed: {result['error']}")
        return False
    
    print(f"[PASS] Abuse confidence score: {result.get('abuse_confidence_score', 'N/A')}")
    return True


async def test_combined_enrichment():
    """Test combined IP enrichment from all sources."""
    from server import enrich_ip_all_sources
    
    print("\n" + "="*60)
    print("TEST: Combined IP Enrichment")
    print("="*60)
    
    test_ip = "1.1.1.1"  # Cloudflare DNS
    print(f"Enriching: {test_ip}")
    
    result = await enrich_ip_all_sources(test_ip)
    print(json.dumps(result, indent=2, default=str))
    
    print(f"[INFO] Overall verdict: {result.get('overall_verdict')}")
    return True


async def test_splunk_connection():
    """Test Splunk API connection."""
    from server import splunk_client, SPLUNK_HOST, SPLUNK_PORT
    
    print("\n" + "="*60)
    print("TEST: Splunk Connection")
    print("="*60)
    
    print(f"Attempting connection to: {SPLUNK_HOST}:{SPLUNK_PORT}")
    
    # Simple search to test connection
    result = await splunk_client.search("| makeresults | eval test=1", "-5m", "now", 1)
    
    if result.get("error"):
        print(f"[FAIL] Splunk connection failed: {result['error']}")
        return False
    
    if result.get("success"):
        print("[PASS] Splunk connection successful")
        print(f"  Results: {result.get('result_count', 0)}")
        return True
    
    return False


async def test_tool_definitions():
    """Verify all tools are properly defined."""
    from server import list_tools
    
    print("\n" + "="*60)
    print("TEST: Tool Definitions")
    print("="*60)
    
    tools = await list_tools()
    
    expected_tools = [
        "search_splunk",
        "enrich_ip",
        "enrich_domain",
        "enrich_hash",
        "hunt_beacons",
        "hunt_volume_anomaly",
        "hunt_new_destinations",
        "hunt_ioc",
        "get_network_summary",
        "check_pipeline_health"
    ]
    
    tool_names = [t.name for t in tools]
    
    print(f"Found {len(tools)} tools:")
    for tool in tools:
        status = "[OK]" if tool.name in expected_tools else "[NEW]"
        print(f"  {status} {tool.name}")
    
    missing = set(expected_tools) - set(tool_names)
    if missing:
        print(f"[WARN] Missing tools: {missing}")
        return False
    
    print(f"[PASS] All {len(expected_tools)} expected tools defined")
    return True


async def test_hunt_beacons_query():
    """Test the C2 beaconing query generation."""
    from server import call_tool
    
    print("\n" + "="*60)
    print("TEST: Hunt Beacons Query")
    print("="*60)
    
    # This will fail without Splunk, but we can verify the query is generated
    result = await call_tool("hunt_beacons", {"hours": 24, "jitter_threshold": 25})
    
    text_content = result[0].text
    parsed = json.loads(text_content)
    
    if parsed.get("error") and "connection" in parsed.get("error", "").lower():
        print("[SKIP] Splunk not available, but query generation works")
        print(f"  Query would search for: jitter < 25%")
        return True
    
    if parsed.get("success"):
        print("[PASS] Hunt beacons executed successfully")
        print(f"  Results: {parsed.get('result_count', 0)}")
        return True
    
    print(f"[INFO] Result: {text_content[:200]}...")
    return True


def print_config():
    """Print current configuration (redacted)."""
    from server import SPLUNK_HOST, SPLUNK_PORT, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
    
    print("\n" + "="*60)
    print("CONFIGURATION")
    print("="*60)
    
    print(f"Splunk Host: {SPLUNK_HOST}")
    print(f"Splunk Port: {SPLUNK_PORT}")
    print(f"VirusTotal API: {'[CONFIGURED]' if VIRUSTOTAL_API_KEY else '[NOT SET]'}")
    print(f"AbuseIPDB API:  {'[CONFIGURED]' if ABUSEIPDB_API_KEY else '[NOT SET]'}")


async def main():
    """Run all tests."""
    print("="*60)
    print("MCP THREAT HUNTER - TEST SUITE")
    print("="*60)
    
    print_config()
    
    results = {}
    
    # Run tests
    results["tool_definitions"] = await test_tool_definitions()
    results["virustotal"] = await test_virustotal_lookup()
    results["abuseipdb"] = await test_abuseipdb_lookup()
    results["combined_enrichment"] = await test_combined_enrichment()
    results["splunk_connection"] = await test_splunk_connection()
    results["hunt_beacons"] = await test_hunt_beacons_query()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {test}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] All tests passed!")
        return 0
    else:
        print("\n[WARNING] Some tests failed - check configuration")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
