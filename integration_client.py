#!/usr/bin/env python3
"""
IntelOwl REST API Automation and SIEM/SOAR Integration Client.

This client interfaces with IntelOwl's REST API to:
1. Submit batch indicators of compromise (IOCs) or files for parallel analysis.
2. Monitor async execution and poll the IntelOwl job server until completion.
3. Calculate consolidated risk assessment scores.
4. Dispatch security alert events (via webhooks or stderr log streams) for SIEM/SOAR.
"""

import sys
import os
import json
import time
import argparse
import logging
from typing import Dict, Any, List, Optional
import requests

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(filename)s:%(lineno)d) - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("IntelOwlIntegrationClient")


class IntelOwlClient:
    """
    Client wrapper for IntelOwl API interactions.
    """
    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.headers = {
            "Authorization": f"Token {self.api_token}",
            "Accept": "application/json"
        }

    def submit_observable(self, value: str, playbooks: List[str]) -> str:
        """
        Submits an observable (IP, Domain, Hash, URL) to IntelOwl for analysis.
        Returns the unique analysis Job ID.
        """
        url = f"{self.base_url}/api/v1/job/analyze_observable/"
        payload = {
            "value": value,
            "playbooks": playbooks
        }

        logger.info(f"Submitting observable '{value}' to IntelOwl...")
        try:
            response = requests.post(
                url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
            job_id = data.get("job_id") or data.get("id")
            if not job_id:
                raise KeyError("API response did not return a job identifier.")
            logger.info(f"Submission successful. Job ID: {job_id}")
            return str(job_id)
        except Exception as e:
            logger.error(f"Failed to submit observable '{value}': {str(e)}")
            raise

    def submit_file(self, file_path: str, playbooks: List[str]) -> str:
        """
        Submits a local file to IntelOwl for asynchronous sandbox/static analysis.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Suspect file path '{file_path}' does not exist.")

        url = f"{self.base_url}/api/v1/job/analyze_file/"
        filename = os.path.basename(file_path)

        logger.info(f"Submitting file '{filename}' to IntelOwl...")
        try:
            with open(file_path, "rb") as f:
                files = {"file": (filename, f)}
                # Some API schemas expect playbooks as form/multipart fields or JSON string.
                data = {"playbooks": json.dumps(playbooks)}

                response = requests.post(
                    url,
                    files=files,
                    data=data,
                    headers={k: v for k, v in self.headers.items() if k != "Content-Type"}, # boundary added automatically
                    verify=self.verify_ssl,
                    timeout=30
                )
                response.raise_for_status()
                res_json = response.json()
                job_id = res_json.get("job_id") or res_json.get("id")
                if not job_id:
                    raise KeyError("API response did not return a job identifier for file submission.")
                logger.info(f"File submission successful. Job ID: {job_id}")
                return str(job_id)
        except Exception as e:
            logger.error(f"Failed to submit file '{filename}': {str(e)}")
            raise

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Retrieves the state of an existing analysis Job from IntelOwl backend.
        Returns job status dictionary containing progress state.
        """
        url = f"{self.base_url}/api/v1/job/{job_id}/"
        try:
            response = requests.get(url, headers=self.headers, verify=self.verify_ssl, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error checking status for Job {job_id}: {str(e)}")
            raise


class CTIIntegrationEngine:
    """
    Orchestration Engine to process threat analysis batch workflows and
    alert SIEM/SOAR platforms on critical findings.
    """
    def __init__(self, client: IntelOwlClient, risk_threshold: int = 70):
        self.client = client
        self.risk_threshold = risk_threshold

    def analyze_batch(self, observables: List[str], playbooks: List[str], poll_interval: int = 5, max_timeout: int = 300) -> List[Dict[str, Any]]:
        """
        Executes parallel or consecutive submissions of observables, monitors them,
        and aggregates findings.
        """
        job_map = {}
        # 1. Dispatch submissions
        for obs in observables:
            try:
                job_id = self.client.submit_observable(obs, playbooks)
                job_map[job_id] = {"observable": obs, "status": "PENDING", "start_time": time.time()}
            except Exception as e:
                logger.error(f"Skipping '{obs}' due to submission failure.")

        # 2. Wait and poll status until complete
        completed_jobs = []
        pending_jobs = list(job_map.keys())
        start_time = time.time()

        while pending_jobs and (time.time() - start_time < max_timeout):
            logger.info(f"Polling status of {len(pending_jobs)} active CTI analyses...")
            still_pending = []

            for j_id in pending_jobs:
                try:
                    res = self.client.get_job_status(j_id)
                    status = res.get("status", "PENDING").upper()

                    if status in ["SUCCESS", "FINISHED", "COMPLETED", "FAILED"]:
                        logger.info(f"Job {j_id} finished with status: {status}")
                        job_map[j_id]["status"] = status
                        job_map[j_id]["raw_results"] = res
                        completed_jobs.append(job_map[j_id])

                        # Evaluate findings and trigger alert if necessary
                        self.evaluate_findings(job_map[j_id])
                    else:
                        still_pending.append(j_id)
                except Exception as err:
                    logger.warning(f"Failed to poll Job {j_id}: {str(err)}. Will retry...")
                    still_pending.append(j_id)

            pending_jobs = still_pending
            if pending_jobs:
                time.sleep(poll_interval)

        if pending_jobs:
            logger.error(f"Timeout reached! {len(pending_jobs)} jobs remained unfinished.")
            for j_id in pending_jobs:
                job_map[j_id]["status"] = "TIMEOUT"
                completed_jobs.append(job_map[j_id])

        return completed_jobs

    def evaluate_findings(self, completed_job: Dict[str, Any]):
        """
        Calculates severity and triggers SIEM alerting on malicious outcomes.
        """
        obs = completed_job["observable"]
        results = completed_job.get("raw_results", {})

        # Calculate score dynamically from multiple configured analyzers in IntelOwl report
        analyzers_report = results.get("analyzers_report", {})

        max_score = 0
        malicious_detectors = []

        # Parse standard IntelOwl report structures
        for analyzer_name, report in analyzers_report.items():
            # Standard IntelOwl analyzers return 'summary', 'risk_score', or specific indicators
            data = report.get("results", {})
            score = 0

            if isinstance(data, dict):
                score = data.get("score") or data.get("risk_score") or data.get("risk") or 0
                # Robust type conversion
                try:
                    score = int(score)
                except (ValueError, TypeError):
                    score = 0

                # Check for explicit malicious flags
                if data.get("malicious") is True or data.get("reputation") == "malicious":
                    score = max(score, 85)
                    malicious_detectors.append(analyzer_name)

            if score > max_score:
                max_score = score
            if score >= self.risk_threshold:
                malicious_detectors.append(analyzer_name)

        completed_job["computed_score"] = max_score
        completed_job["malicious_detectors"] = list(set(malicious_detectors))

        is_malicious = max_score >= self.risk_threshold or len(malicious_detectors) > 0

        if is_malicious:
            completed_job["assessment"] = "Malicious"
            self.trigger_siem_alert(obs, max_score, completed_job["malicious_detectors"], results)
        else:
            completed_job["assessment"] = "Clean/Suspicious"
            logger.info(f"Observable '{obs}' assessment: SAFE (Score: {max_score})")

    def trigger_siem_alert(self, observable: str, score: int, detectors: List[str], full_report: Dict[str, Any]):
        """
        Dispatches SIEM/SOAR threat events.
        """
        alert_payload = {
            "event_type": "THREAT_INTELLIGENCE_ALERT",
            "source": "IntelOwl-Automated-Orchestrator",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "severity": "CRITICAL" if score >= 85 else "HIGH",
            "indicator": observable,
            "calculated_score": score,
            "detecting_analyzers": detectors,
            "summary": f"Malicious IOC detected via automatic IntelOwl scan: {observable} [Score: {score}/100]"
        }

        # Log to standard error to trigger container alerting streams
        sys.stderr.write(f"\n[ALERT - SECOP CONSOLE] {json.dumps(alert_payload, indent=2)}\n\n")

        # Webhook dispatch payload (SIEM/SOAR mock integration)
        webhook_url = os.getenv("SOAR_WEBHOOK_URL")
        if webhook_url:
            try:
                requests.post(webhook_url, json=alert_payload, timeout=5)
                logger.info(f"SIEM Webhook dispatched successfully to {webhook_url}")
            except Exception as e:
                logger.error(f"Failed to post to SIEM Webhook: {str(e)}")


def run_standalone_test():
    """
    Performs a local end-to-end integration test with mock configurations
    to demonstrate and verify orchestration engine logic.
    """
    logger.info("Starting local proof-of-concept verification...")

    # Mocking standard requests interactions for fully independent validation
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        def json(self):
            return self.json_data
        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(f"HTTP Error {self.status_code}")

    original_post = requests.post
    original_get = requests.get

    # Counter to simulate job advancement on successive polls
    poll_counter = {"clicks": 0}

    def mock_post(url, *args, **kwargs):
        if "analyze_observable" in url:
            return MockResponse({"job_id": "job_12345_mock"}, 200)
        return original_post(url, *args, **kwargs)

    def mock_get(url, *args, **kwargs):
        if "job/job_12345_mock" in url:
            poll_counter["clicks"] += 1
            if poll_counter["clicks"] < 2:
                return MockResponse({"status": "PENDING"}, 200)
            else:
                # Mock result payload containing custom analyzer details
                return MockResponse({
                    "status": "SUCCESS",
                    "analyzers_report": {
                        "CustomThreatFeedAnalyzer": {
                            "results": {
                                "score": 90,
                                "reputation": "malicious",
                                "assessment": "Malicious"
                            }
                        }
                    }
                }, 200)
        return original_get(url, *args, **kwargs)

    # Patch requests during local simulation run
    requests.post = mock_post
    requests.get = mock_get

    try:
        client = IntelOwlClient(base_url="http://localhost:8000", api_token="test_token_123")
        engine = CTIIntegrationEngine(client=client, risk_threshold=70)

        logger.info("Dispatching CTI pipeline for malicious observable simulation...")
        results = engine.analyze_batch(
            observables=["malicious-command-control.xyz"],
            playbooks=["custom_threat_feed_playbook"],
            poll_interval=1
        )

        logger.info(f"Batch analysis complete. Consolidated response: {json.dumps(results, indent=2)}")
        assert len(results) == 1
        assert results[0]["computed_score"] == 90
        assert results[0]["assessment"] == "Malicious"
        logger.info("Local engine proof-of-concept validation: SUCCESS!")
    finally:
        # Restore original requests functions
        requests.post = original_post
        requests.get = original_get


def main():
    parser = argparse.ArgumentParser(description="IntelOwl Threat Intelligence REST Integration Script")
    parser.add_argument("--url", default="http://localhost:80", help="Base URL of IntelOwl instance")
    parser.add_argument("--token", default=os.getenv("INTELOWL_API_TOKEN", "MOCK_TOKEN"), help="API Token for IntelOwl Server")
    parser.add_argument("--observable", help="Single observable string (IP, Domain, URL, Hash) to submit")
    parser.add_argument("--file", help="Local suspect file path to submit")
    parser.add_argument("--playbooks", default="custom_threat_feed_playbook", help="Comma-separated playbook list to trigger")
    parser.add_argument("--threshold", type=int, default=70, help="Risk score threshold to raise incident alerts (0-100)")
    parser.add_argument("--test", action="store_true", help="Run local self-test mock scenario and exit")

    args = parser.parse_args()

    if args.test:
        run_standalone_test()
        sys.exit(0)

    if not args.observable and not args.file:
        parser.print_help()
        sys.exit(1)

    # Initialize components
    client = IntelOwlClient(base_url=args.url, api_token=args.token)
    engine = CTIIntegrationEngine(client=client, risk_threshold=args.threshold)
    playbook_list = [p.strip() for p in args.playbooks.split(",")]

    if args.observable:
        logger.info(f"Executing automation workflow on observable: {args.observable}")
        results = engine.analyze_batch(observables=[args.observable], playbooks=playbook_list)
        print(json.dumps(results, indent=2))

    elif args.file:
        logger.info(f"Executing automation workflow on suspect file: {args.file}")
        try:
            job_id = client.submit_file(file_path=args.file, playbooks=playbook_list)
            # Poll single file status
            start_time = time.time()
            finished = False
            while not finished and (time.time() - start_time < 300):
                res = client.get_job_status(job_id)
                status = res.get("status", "PENDING").upper()
                if status in ["SUCCESS", "FINISHED", "COMPLETED", "FAILED"]:
                    logger.info(f"File analysis Job {job_id} concluded with status: {status}")
                    print(json.dumps(res, indent=2))
                    finished = True
                else:
                    time.sleep(5)
            if not finished:
                logger.error("Analysis timed out.")
        except Exception as e:
            logger.error(f"Failed to execute file workflow: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()
