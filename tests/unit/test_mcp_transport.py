# =============================================================================
# tests/unit/test_mcp_transport.py
# OWNER: Lead / Infra Hire
# MARKERS: unit (Docker not required — subprocess is mocked)
# PURPOSE: Tests for agents/shared/mcp_transport.py
#          Critical: verifies output truncation and patch scope enforcement.
# RUN: pytest tests/unit/test_mcp_transport.py -v
# =============================================================================

import pytest
from unittest.mock import patch, MagicMock

from agents.shared.mcp_transport import (
    truncate_output,
    MAX_TOOL_OUTPUT_TOKENS,
    RedTeamTransport,
    BlueTeamTransport,
    RED_TEAM_ALLOWED_TOOLS,
    BLUE_TEAM_ALLOWED_TOOLS,
)


# ---------------------------------------------------------------------------
# Output Truncation (CRITICAL — never bypass)
# ---------------------------------------------------------------------------

class TestOutputTruncation:

    def test_short_output_not_truncated(self):
        short_text = "open ports: 80, 443"
        result, was_truncated = truncate_output(short_text)
        assert result == short_text
        assert was_truncated is False

    def test_long_output_is_truncated(self):
        # Generate text that exceeds MAX_TOOL_OUTPUT_TOKENS * 4 chars
        long_text = "a" * (MAX_TOOL_OUTPUT_TOKENS * 4 + 1000)
        result, was_truncated = truncate_output(long_text)
        assert was_truncated is True
        assert "[OUTPUT TRUNCATED" in result

    def test_truncated_output_within_token_limit(self):
        long_text = "x" * 100_000
        result, _ = truncate_output(long_text)
        estimated_tokens = len(result) // 4
        assert estimated_tokens <= MAX_TOOL_OUTPUT_TOKENS + 50  # small buffer for truncation message

    def test_custom_max_tokens_respected(self):
        text = "a" * 2000  # ~500 tokens
        result, was_truncated = truncate_output(text, max_tokens=100)
        assert was_truncated is True
        assert len(result) // 4 <= 150  # within 100 + truncation message overhead


# ---------------------------------------------------------------------------
# Red Team Transport — Tool Allowlist
# ---------------------------------------------------------------------------

class TestRedTeamTransport:

    def test_disallowed_tool_rejected(self):
        rt = RedTeamTransport()
        result = rt.run_tool("rm", ["-rf"], "target")
        assert result.success is False
        assert "not permitted" in result.error

    def test_allowed_tools_list_not_empty(self):
        assert len(RED_TEAM_ALLOWED_TOOLS) > 0

    def test_nmap_in_allowed_tools(self):
        assert "nmap" in RED_TEAM_ALLOWED_TOOLS

    def test_curl_in_allowed_tools(self):
        assert "curl" in RED_TEAM_ALLOWED_TOOLS

    def test_successful_tool_returns_truncated_output(self):
        rt = RedTeamTransport()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "PORT   STATE SERVICE\n80/tcp open  http\n"
        mock_result.stderr = ""

        with patch("agents.shared.mcp_transport.subprocess.run", return_value=mock_result):
            result = rt.run_tool("nmap", ["-sV"], "localhost")
            assert result.success is True
            assert result.token_estimate > 0

    def test_nmap_parse_extracts_open_ports(self):
        rt = RedTeamTransport()
        sample_nmap = (
            "PORT     STATE SERVICE VERSION\n"
            "80/tcp   open  http    Apache 2.4.51\n"
            "443/tcp  open  https   nginx 1.21\n"
            "3306/tcp open  mysql   MySQL 8.0\n"
        )
        parsed = rt._parse_nmap(sample_nmap)
        assert "ports" in parsed
        assert len(parsed["ports"]) == 3
        assert parsed["ports"][0]["port"] == "80/tcp"
        assert parsed["ports"][0]["service"] == "http"


# ---------------------------------------------------------------------------
# Blue Team Transport — Patch Scope Enforcement (CRITICAL)
# ---------------------------------------------------------------------------

class TestBlueTeamPatchScopeEnforcement:

    def test_patch_within_allowed_path_accepted(self):
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/wp-includes/class-wpdb.php\n"
            "+++ b/wp-includes/class-wpdb.php\n"
            "@@ -140,7 +140,7 @@\n"
            "-    $query = \"SELECT * FROM users WHERE id = $id\";\n"
            "+    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is None  # None = valid, no violation

    def test_patch_outside_allowed_path_rejected(self):
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/wp-config.php\n"
            "+++ b/wp-config.php\n"
            "@@ -1,3 +1,3 @@\n"
            "-define('DB_PASSWORD', 'secret');\n"
            "+define('DB_PASSWORD', 'hacked');\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]  # config.php not allowed
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is not None  # not None = violation found
        assert "wp-config.php" in result

    def test_patch_modifying_multiple_files_all_must_be_allowed(self):
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/allowed_file.php\n"
            "+++ b/allowed_file.php\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
            "--- a/not_allowed.php\n"
            "+++ b/not_allowed.php\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["allowed_file.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is not None  # violation because not_allowed.php is in the patch

    def test_blue_team_cannot_use_offensive_tools(self):
        """Blue Team must NOT be able to run nmap or other offensive tools."""
        assert "nmap"        not in BLUE_TEAM_ALLOWED_TOOLS
        assert "gobuster"    not in BLUE_TEAM_ALLOWED_TOOLS
        assert "feroxbuster" not in BLUE_TEAM_ALLOWED_TOOLS
        assert "nikto"       not in BLUE_TEAM_ALLOWED_TOOLS


# ---------------------------------------------------------------------------
# Patch Scope — Regression cases for the Phase 0 security fix
#
# Both of these would have passed under the original implementation:
#   1. lstrip("ab/") over-stripped paths starting with 'a', 'b', or '/'
#   2. `allowed in modified` substring match accepted path-traversal payloads
# ---------------------------------------------------------------------------

class TestBlueTeamPatchScopeSecurityRegressions:

    def test_path_traversal_attempt_is_rejected(self):
        """
        Original bug: `allowed in modified` substring check.
        A path that contains an allowed path as a substring but resolves
        outside the repo root must be rejected.
        """
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/wp-includes/class-wpdb.php/../../wp-config.php\n"
            "+++ b/wp-includes/class-wpdb.php/../../wp-config.php\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is not None, "Path traversal must be rejected, not accepted"

    def test_filename_starting_with_a_is_not_over_stripped(self):
        """
        Original bug: lstrip('ab/') treated the prefix as a set of characters.
        A file named 'apps/foo.py' became 'pps/foo.py' and silently mismatched.
        """
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/apps/foo.py\n"
            "+++ b/apps/foo.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["apps/foo.py"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is None, (
            f"File starting with 'a' should match its allowed path exactly. "
            f"Got: {result!r}"
        )

    def test_filename_starting_with_b_is_not_over_stripped(self):
        """Same as above, for paths starting with 'b' — e.g. 'bin/runner.sh'."""
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/bin/runner.sh\n"
            "+++ b/bin/runner.sh\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["bin/runner.sh"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is None, f"'bin/...' should match allowed exactly. Got: {result!r}"

    def test_evil_prefix_does_not_satisfy_endswith_match(self):
        """
        Original bug: `modified.endswith(allowed)` accepted
        'evil-wp-includes/class-wpdb.php' as a match for 'wp-includes/class-wpdb.php'.
        """
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/evil-wp-includes/class-wpdb.php\n"
            "+++ b/evil-wp-includes/class-wpdb.php\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is not None, "Evil-prefixed path must not pass via endswith"

    def test_absolute_path_in_diff_header_is_rejected(self):
        bt = BlueTeamTransport()
        patch_diff = (
            "--- /etc/passwd\n"
            "+++ /etc/passwd\n"
            "@@ -1 +1 @@\n"
            "-root:x:0:0::/root:/bin/bash\n"
            "+root:x:0:0::/root:/bin/bash\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is not None
        assert "absolute" in result.lower()

    def test_dev_null_in_diff_header_is_ignored(self):
        """File deletion in a unified diff uses /dev/null on one side."""
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/wp-includes/class-wpdb.php\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-line1\n"
            "-line2\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is None

    def test_diff_header_with_git_timestamp_suffix_is_parsed(self):
        """
        Real git diffs include '\\t<timestamp>' after the filename. The previous
        split-on-whitespace logic happened to work for the simple case but
        broke when timestamps contained spaces.
        """
        bt = BlueTeamTransport()
        patch_diff = (
            "--- a/wp-includes/class-wpdb.php\t2024-01-01 12:00:00 +0000\n"
            "+++ b/wp-includes/class-wpdb.php\t2024-01-02 12:00:00 +0000\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        allowed_paths = ["wp-includes/class-wpdb.php"]
        result = bt._validate_patch_scope(patch_diff, allowed_paths)
        assert result is None, f"Timestamp suffix should not break parsing. Got: {result!r}"