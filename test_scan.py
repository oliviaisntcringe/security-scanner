import asyncio
from app.scanners.ml_scanner import MLScanner
from app.utils.helpers import LOG

async def test_scan():
    print("Creating MLScanner instance...")
    scanner = MLScanner()
    
    print("Initializing session...")
    await scanner.init_session()
    print("Session initialized successfully")
    
    print("Starting scan on http://testphp.vulnweb.com/...")
    results = await scanner.scan_all("http://testphp.vulnweb.com/")
    
    print(f"Scan completed! Found {len(results)} potential vulnerabilities")
    
    if results:
        print("\nVulnerability types found:")
        vuln_types = {}
        for result in results:
            vuln_type = result.get('type', 'unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        for vuln_type, count in vuln_types.items():
            print(f"- {vuln_type}: {count}")
    
    print("\nCleaning up...")
    await scanner.cleanup()
    print("Session cleaned up successfully")
    
    return "Scan test completed!"

if __name__ == "__main__":
    try:
        result = asyncio.run(test_scan())
        print(result)
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        print(traceback.format_exc()) 