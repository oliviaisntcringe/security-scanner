"""
ML-based vulnerability detector — wraps the trained sklearn models.
"""
from __future__ import annotations

import pickle
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from scanner.config import MODELS_DIR, ML_CONFIDENCE_THRESHOLD
from scanner.utils import http as http_util
from scanner.utils.output import info, warn

_VULN_TYPES = ["xss", "sqli", "csrf", "ssrf", "lfi", "rce"]


class MLDetector:
    def __init__(self) -> None:
        self.models: Dict[str, Any]  = {}
        self.features: Dict[str, Any] = {}
        self.scalers: Dict[str, Any]  = {}
        self._load()

    def _load(self) -> None:
        for vtype in _VULN_TYPES:
            mp = MODELS_DIR / f"{vtype}_model.pkl"
            fp = MODELS_DIR / f"{vtype}_features.pkl"
            sp = MODELS_DIR / f"{vtype}_scaler.pkl"
            if mp.exists() and fp.exists() and sp.exists():
                try:
                    self.models[vtype]   = pickle.loads(mp.read_bytes())
                    self.features[vtype] = pickle.loads(fp.read_bytes())
                    self.scalers[vtype]  = pickle.loads(sp.read_bytes())
                except Exception as e:
                    warn(f"ML: could not load {vtype} model — {e}")

    def available(self) -> List[str]:
        return list(self.models.keys())

    async def scan(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> List[Dict[str, Any]]:
        if not self.models:
            return []

        resp = await http_util.get(session, url, timeout=15)
        if resp is None:
            return []

        try:
            html = await resp.text(errors="ignore")
        except Exception:
            return []

        features = self._extract_features(url, html, resp)
        if not features:
            return []

        findings: List[Dict[str, Any]] = []
        for vtype, model in self.models.items():
            try:
                feat_names = self.features.get(vtype, [])
                scaler     = self.scalers.get(vtype)
                if not feat_names:
                    continue

                vec = [features.get(f, 0) for f in feat_names]
                if len(vec) < len(feat_names):
                    vec += [0] * (len(feat_names) - len(vec))

                import numpy as np
                X = np.array(vec).reshape(1, -1)
                if scaler:
                    X = scaler.transform(X)

                proba = model.predict_proba(X)[0]
                confidence = float(max(proba))
                predicted  = int(model.predict(X)[0])

                if predicted == 1 and confidence >= ML_CONFIDENCE_THRESHOLD:
                    findings.append({
                        "type":       vtype,
                        "severity":   _sev(vtype),
                        "url":        url,
                        "parameter":  "N/A (ML detection)",
                        "payload":    "N/A",
                        "context":    "ml-detection",
                        "evidence":   f"ML confidence {confidence:.2f}",
                        "details":    f"ML model detected potential {vtype.upper()} (confidence {confidence:.0%})",
                        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "confidence": confidence,
                    })
            except Exception:
                continue

        return findings

    def _extract_features(
        self,
        url: str,
        html: str,
        resp: aiohttp.ClientResponse,
    ) -> Dict[str, float]:
        soup = BeautifulSoup(html, "html.parser")
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        f: Dict[str, float] = {}

        # URL features
        f["url_length"]          = len(url)
        f["param_count"]         = len(params)
        f["has_query"]           = float(bool(parsed.query))
        f["path_depth"]          = parsed.path.count("/")
        f["has_file_ext"]        = float("." in (parsed.path.split("/")[-1] or ""))

        # HTML features
        text = soup.get_text()
        f["html_length"]         = len(html)
        f["form_count"]          = len(soup.find_all("form"))
        f["input_count"]         = len(soup.find_all("input"))
        f["script_count"]        = len(soup.find_all("script"))
        f["link_count"]          = len(soup.find_all("a"))
        f["has_password_field"]  = float(bool(soup.find("input", {"type": "password"})))
        f["has_csrf_token"]      = float(bool(soup.find("input", {"name": re.compile(r"csrf", re.I)})))
        f["has_login_form"]      = float("login" in html.lower() or "sign in" in html.lower())

        # Response features
        f["status_code"]         = float(resp.status)
        f["content_length"]      = float(resp.headers.get("Content-Length", 0) or 0)
        f["has_csp"]             = float("content-security-policy" in str(resp.headers).lower())
        f["has_xframe"]          = float("x-frame-options" in str(resp.headers).lower())
        f["has_xss_protection"]  = float("x-xss-protection" in str(resp.headers).lower())
        f["cors_wildcard"]       = float(resp.headers.get("Access-Control-Allow-Origin", "") == "*")

        # Keyword presence
        f["sql_errors"]          = float(bool(re.search(r"sql syntax|mysql_|ora-\d{4}", html, re.I)))
        f["file_inclusion"]      = float("root:x:" in html or "[boot loader]" in html)
        f["xss_reflected"]       = float("<script>" in html and "alert" in html)
        f["server_error"]        = float(resp.status >= 500)

        return f


def _sev(vtype: str) -> str:
    return {"sqli": "critical", "rce": "critical", "file_inclusion": "critical",
            "xss": "high", "ssrf": "high", "lfi": "critical"}.get(vtype, "medium")
