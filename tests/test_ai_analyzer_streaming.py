"""Tests for Ollama response streaming and speed-oriented generation limits."""

import json
import unittest
from unittest import mock

import ai_analyzer


class OllamaStreamingTests(unittest.TestCase):
    def test_analyze_alert_streams_tokens_and_uses_output_limit(self):
        response = mock.Mock()
        response.iter_lines.return_value = [
            json.dumps({"response": "Event ", "done": False}).encode(),
            json.dumps({"response": "looks suspicious.", "done": False}).encode(),
            json.dumps({"response": "", "done": True}).encode(),
        ]
        received_tokens = []
        with mock.patch.object(ai_analyzer.session, "post", return_value=response) as post:
            result = ai_analyzer.analyze_alert(
                {"id": 42, "event_type": "TEST"}, on_token=received_tokens.append
            )

        self.assertEqual(result, "Event looks suspicious.")
        self.assertEqual(received_tokens, ["Event ", "looks suspicious."])
        request = post.call_args.kwargs
        self.assertTrue(request["stream"])
        self.assertTrue(request["json"]["stream"])
        self.assertLessEqual(request["json"]["options"]["num_predict"], 500)
        response.raise_for_status.assert_called_once()


if __name__ == "__main__":
    unittest.main()
