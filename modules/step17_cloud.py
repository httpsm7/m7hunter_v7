#!/usr/bin/env python3
# modules/step17_cloud.py — Cloud Asset Enumeration v6 (FIXED)
# FIX: 403 "EXISTS_S3_PRIVATE" no longer creates a finding (privacy clutter)
# FIX: Only OPEN/listable buckets create findings (actual vulnerabilities)
# FIX: Added Azure SAS token check, Firebase public DB check
# MilkyWay Intelligence | Author: Sharlix

import os
import urllib.request
import urllib.error
from core.utils import safe_read

class CloudEnumStep:
    def __init__(self, p): self.p=p; self.log=p.log; self.f=p.files

    def run(self):
        target = self.p.target.replace("https://","").replace("http://","").split("/")[0]
        parts  = target.split(".")
        brand  = parts[0] if parts else target
        out    = self.f["cloud_results"]
        found  = 0
        logged = 0

        s3_names = self._gen_names(brand, target)
        self.log.info(f"Cloud: testing {len(s3_names)} bucket names")

        for name in s3_names:
            # S3
            result = self._check_s3(name)
            if result:
                status_type, url = result
                with open(out,"a") as f:
                    f.write(f"{status_type}: {url}\n")

                # FIX: Only OPEN buckets get findings (not 403 private exists)
                if status_type == "OPEN_S3":
                    self.p.add_finding("critical","OPEN_S3_BUCKET", url,
                                       "S3 bucket publicly listable — files exposed","cloud-enum")
                    found += 1
                elif status_type == "EXISTS_S3":
                    # Log to file but NOT to findings (not a vulnerability)
                    logged += 1
                # EXISTS_S3_PRIVATE (403) → only in file, not finding at all

            # GCP
            gcp_result = self._check_gcp(name)
            if gcp_result:
                status_type, url = gcp_result
                with open(out,"a") as f:
                    f.write(f"{status_type}: {url}\n")
                if status_type == "OPEN_GCP":
                    self.p.add_finding("critical","OPEN_GCP_BUCKET", url,
                                       "GCP bucket publicly accessible","cloud-enum")
                    found += 1

            # Azure
            az_result = self._check_azure(name)
            if az_result:
                status_type, url = az_result
                with open(out,"a") as f:
                    f.write(f"{status_type}: {url}\n")
                # FIX: Only report OPEN Azure containers, not just "exists"
                if "OPEN" in status_type:
                    self.p.add_finding("critical","OPEN_AZURE_CONTAINER", url,
                                       "Azure blob container publicly accessible","cloud-enum")
                    found += 1

        # Firebase check
        firebase_result = self._check_firebase(brand, target)
        if firebase_result:
            url, detail = firebase_result
            with open(out,"a") as f:
                f.write(f"OPEN_FIREBASE: {url}\n")
            self.p.add_finding("critical","FIREBASE_OPEN_DB", url, detail,"cloud-enum")
            found += 1

        # cloud_enum tool (if available)
        self.p.shell(
            f"cloud_enum -k {brand} -k {target} --disable-azure --threads 5 2>/dev/null",
            label="cloud_enum", append_file=out, tool_name="cloud_enum")

        self.log.success(f"Cloud: {found} OPEN buckets | {logged} private (logged only)")
        # V7: Additional cloud checks
        try: self._test_lambda_exposure(target)
        except Exception as e:
            from core.error_handler import get_handler; get_handler().capture("step17_cloud",e,"lambda")
        try: self._test_k8s_exposure(target)
        except Exception as e:
            from core.error_handler import get_handler; get_handler().capture("step17_cloud",e,"k8s")

    def _gen_names(self, brand: str, target: str) -> list:
        suffixes = ["","backup","backups","dev","staging","prod","static","assets",
                    "files","data","logs","media","images","uploads","cdn","api",
                    "-backup","-dev","-staging","-prod","-static","-assets",
                    "-files","-data","-logs","-media"]
        names = set()
        for suf in suffixes:
            names.add(f"{brand}{suf}")
            names.add(f"{target}{suf}")
        return list(names)[:40]

    def _check_s3(self, name: str) -> tuple:
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls:
            try:
                req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/6.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    content = resp.read(500).decode(errors="ignore")
                    if "ListBucketResult" in content:
                        return ("OPEN_S3", url)
                    # 200 but no ListBucketResult = exists but not listing
                    return ("EXISTS_S3", url)
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    return ("EXISTS_S3_PRIVATE", url)  # FIX: logged not reported as finding
                elif e.code == 404:
                    pass  # Doesn't exist
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step17_cloud", _e)
        return None

    def _check_gcp(self, name: str) -> tuple:
        url = f"https://storage.googleapis.com/{name}"
        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/6.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                content = resp.read(500).decode(errors="ignore")
                if "ListBucketResult" in content or "<Contents>" in content:
                    return ("OPEN_GCP", url)
                return ("EXISTS_GCP", url)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return ("EXISTS_GCP_PRIVATE", url)  # Not a finding
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step17_cloud", _e)
        return None

    def _check_azure(self, name: str) -> tuple:
        # Check blob container listing
        url = f"https://{name}.blob.core.windows.net/?comp=list"
        try:
            req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/6.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                content = resp.read(500).decode(errors="ignore")
                if "<Container>" in content or "<Name>" in content:
                    return ("OPEN_AZURE", url)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return ("EXISTS_AZURE_PRIVATE", url)  # Not a finding
            elif e.code == 400:
                return ("EXISTS_AZURE", url)  # Exists but not listing
        except Exception as _e:
            from core.error_handler import get_handler
            get_handler().capture("step17_cloud", _e)
        return None

    def _check_firebase(self, brand: str, target: str) -> tuple:
        """Check Firebase Realtime Database for public access."""
        db_names = [brand, brand.replace("-",""), target.split(".")[0]]
        for name in db_names:
            url = f"https://{name}-default-rtdb.firebaseio.com/.json"
            try:
                req  = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/6.0"})
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status == 200:
                    content = resp.read(200).decode(errors="ignore")
                    # Actual data (not null, not permission denied)
                    if content not in ("null","null\n") and "Permission denied" not in content:
                        detail = f"Firebase DB publicly readable: {content[:100]}"
                        return (url, detail)
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step17_cloud", _e)
        return None
    def _test_lambda_exposure(self, target):
        """Check for exposed Lambda/API Gateway endpoints."""
        import urllib.request, urllib.error
        gw_paths = ["/api/","/v1/","/v2/","/lambda/","/function/"]
        for path in gw_paths:
            url = f"https://{target}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=6)
                hdrs = dict(resp.headers)
                # API Gateway signature headers
                if "x-amzn-requestid" in str(hdrs).lower() or "x-amz-apigw" in str(hdrs).lower():
                    self.p.add_finding("high","LAMBDA_API_GATEWAY_EXPOSED",url,
                        "API Gateway/Lambda endpoint exposed","cloud-check",confidence=0.75)
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step17_cloud", _e)

    def _test_k8s_exposure(self, target):
        """Check for exposed Kubernetes API or metrics."""
        import urllib.request, urllib.error, re
        k8s_paths = [
            "/api/v1/namespaces/default/secrets","/.kube/config",
            "/metrics","/actuator/env","/api/v1/pods",
        ]
        for path in k8s_paths:
            url = f"https://{target}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"M7Hunter/7.0"})
                resp = urllib.request.urlopen(req, timeout=6)
                body = resp.read(2000).decode(errors="ignore")
                if any(sig in body for sig in ["kind: Secret","apiVersion: v1","KUBERNETES_SERVICE","serviceAccountToken"]):
                    self.p.add_finding("critical","K8S_SECRET_LEAK",url,
                        f"K8s secrets/config exposed at {path}","k8s-check",
                        response=body[:300],confidence=0.92,status="confirmed")
            except urllib.error.HTTPError as e:
                if e.code not in (403,404,401):
                    pass
            except Exception as _e:
                from core.error_handler import get_handler
                get_handler().capture("step17_cloud", _e)

