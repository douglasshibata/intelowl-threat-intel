import sys
import os
import unittest

# Adjust python path to include our source folder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custom_analyzer import CustomThreatFeedAnalyzer, AnalyzerRunException
from integration_client import IntelOwlClient, CTIIntegrationEngine


class TestCustomThreatFeedAnalyzer(unittest.TestCase):
    """
    Tests validation, mock responses, and formatting logic of CustomThreatFeedAnalyzer.
    """
    def setUp(self):
        self.analyzer = CustomThreatFeedAnalyzer()
        # Initialize with standard test options
        self.analyzer.set_config({
            "api_url": "https://api.test-threatintel.internal/v1",
            "api_key_name": "TEST_FEED_KEY",
            "timeout": 5,
            "risk_threshold": 70
        })

    def test_observable_validation(self):
        """
        Verify that correct observables are classified and invalid ones raise AnalyzerRunException.
        """
        # Valid cases
        self.assertEqual(self.analyzer.validate_observable("1.1.1.1"), "ip")
        self.assertEqual(self.analyzer.validate_observable("8.8.8.8"), "ip")
        self.assertEqual(self.analyzer.validate_observable("malicious-c2.com"), "domain")
        self.assertEqual(self.analyzer.validate_observable("sub.domain.corp.net"), "domain")

        # Invalid cases
        with self.assertRaises(AnalyzerRunException):
            self.analyzer.validate_observable("invalid_ip_999.999.999.999")
        with self.assertRaises(AnalyzerRunException):
            self.analyzer.validate_observable("http://malicious-url.com") # Not an bare IP/domain FQDN
        with self.assertRaises(AnalyzerRunException):
            self.analyzer.validate_observable("hash_64_characters_8f9e2a4b3d1c")

    def test_mock_response_and_formatting_safe(self):
        """
        Verify formatting of a safe observable.
        """
        self.analyzer.observable_name = "safe-google-dns.com"
        # Enable test mode to bypass API call during tests
        os.environ["INTELOWL_TEST_MODE"] = "true"

        report = self.analyzer.run()

        self.assertTrue(report["success"])
        self.assertEqual(report["observable"]["value"], "safe-google-dns.com")
        self.assertEqual(report["observable"]["type"], "domain")

        # Safe assess
        self.assertFalse(report["summary"]["malicious"])
        self.assertLess(report["summary"]["score"], 70)
        self.assertEqual(report["summary"]["assessment"], "Clean")

    def test_mock_response_and_formatting_malicious(self):
        """
        Verify formatting of a malicious/suspicious observable.
        """
        self.analyzer.observable_name = "1.1.1.1" # Explicitly mocked as malicious
        os.environ["INTELOWL_TEST_MODE"] = "true"

        report = self.analyzer.run()

        self.assertTrue(report["success"])
        self.assertEqual(report["observable"]["value"], "1.1.1.1")
        self.assertEqual(report["observable"]["type"], "ip")

        # Malicious assess
        self.assertTrue(report["summary"]["malicious"])
        self.assertEqual(report["summary"]["score"], 95)
        self.assertEqual(report["summary"]["assessment"], "Malicious")
        self.assertIn("phishing", report["details"]["categories"])


class TestCTIIntegrationEngine(unittest.TestCase):
    """
    Tests the CTI automation client's score consolidation and alerting logic.
    """
    def test_scoring_and_alerting_safe(self):
        # Create a mock engine with a threshold of 75
        client = IntelOwlClient(base_url="http://mock-server", api_token="test_token")
        engine = CTIIntegrationEngine(client=client, risk_threshold=75)

        completed_job = {
            "observable": "clean-example.com",
            "raw_results": {
                "status": "SUCCESS",
                "analyzers_report": {
                    "SafeAnalyzer": {
                        "results": {
                            "score": 10,
                            "reputation": "clean"
                        }
                    }
                }
            }
        }

        engine.evaluate_findings(completed_job)

        self.assertEqual(completed_job["computed_score"], 10)
        self.assertEqual(completed_job["assessment"], "Clean/Suspicious")
        self.assertEqual(len(completed_job["malicious_detectors"]), 0)

    def test_scoring_and_alerting_malicious(self):
        client = IntelOwlClient(base_url="http://mock-server", api_token="test_token")
        engine = CTIIntegrationEngine(client=client, risk_threshold=70)

        completed_job = {
            "observable": "malicious-c2.xyz",
            "raw_results": {
                "status": "SUCCESS",
                "analyzers_report": {
                    "CustomThreatFeedAnalyzer": {
                        "results": {
                            "score": 90,
                            "reputation": "malicious"
                        }
                    },
                    "SecondAnalyzer": {
                        "results": {
                            "score": 45,
                            "reputation": "suspicious"
                        }
                    }
                }
            }
        }

        engine.evaluate_findings(completed_job)

        # Consolidated score should be the maximum of all reports
        self.assertEqual(completed_job["computed_score"], 90)
        self.assertEqual(completed_job["assessment"], "Malicious")
        self.assertIn("CustomThreatFeedAnalyzer", completed_job["malicious_detectors"])


if __name__ == "__main__":
    unittest.main()
