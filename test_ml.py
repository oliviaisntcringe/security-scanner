import asyncio
import sys
from app.scanners.ml_scanner import MLScanner

async def main():
    # Create scanner and load models
    scanner = MLScanner()
    
    # Test URL and vulnerability type
    url = "https://geekflare.com/technology/"
    vuln_type = "ssrf"
    
    print(f"[*] Testing prediction for {vuln_type} on {url}")
    
    # Extract features
    print(f"[*] Extracting features...")
    features = await scanner.extract_features(url, vuln_type)
    if features is not None:
        print(f"[+] Extracted features shape: {features.shape}")
    else:
        print(f"[!] Failed to extract features")
        return
    
    # Try prediction
    print(f"[*] Running prediction...")
    result = await scanner.predict_vulnerability(url, vuln_type)
    
    print(f"[*] Prediction result: {result}")
    
    # Clean up
    await scanner.cleanup()

if __name__ == "__main__":
    asyncio.run(main()) 