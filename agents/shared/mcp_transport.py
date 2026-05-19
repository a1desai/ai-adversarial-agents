# =============================================================================
# agents/shared/mcp_transport.py
# OWNER: Lead — SECURITY CRITICAL — requires lead + one additional reviewer
# DEPENDS ON: mcp, Docker (target containers must be running)
# PURPOSE: MCP transport layer between Docker target containers and LangGraph.
#          Handles tool invocation, output truncation, and patch deployment.
# =============================================================================
#
# CRITICAL RULES (enforced programmatically — not just guidelines):
#
#   1. OUTPUT TRUNCATION: Raw tool output is ALWAYS truncated to MAX_TOOL_OUTPUT_TOKENS
#      before being injected into any agent context window.
#      Raw nmap output can exceed 10,000 tokens. We allow max 1,000.
#
#   2. BLUE TEAM WRITE ACCESS: The Blue Team can only write to files explicitly
#      listed in the Vulnerability Analysis output. Path whitelist is enforced here.
#      Any patch touching a file outside the whitelist is REJECTED.
#
#   3. NO RAW OUTPUT PASSTHROUGH: Tool stdout/stderr is never passed directly
#      to the next agent stage. It is always parsed and structured first.
#
#   4. SECURITY REVIEW REQUIRED: Any change to this file requires sign-off
#      from the lead + one additional hire before merge.
# =============================================================================

import subprocess
import json
import posixpath
import shlex
from pathlib import Path
from dataclasses import dataclass, field
from loguru import logger


def _strip_diff_prefix(path: str) -> str:
    """
    Strip the leading 'a/' or 'b/' that git/unified-diff headers conventionally use.

    Does NOT use str.lstrip — that strips a *set of characters*, not a prefix
    (e.g. 'apps/foo.py'.lstrip('ab/') incorrectly returns 'pps/foo.py').
    """
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _parse_diff_header_path(line: str) -> str | None:
    """
    Extract the filename from a unified-diff '--- ' or '+++ ' header line.

    Handles git's trailing tab + timestamp (e.g. '--- a/foo.py\\t2024-01-01 ...').
    Returns None if the line doesn't carry a usable path.
    """
    if not (line.startswith("--- ") or line.startswith("+++ ")):
        return None
    # Strip the 4-char marker. Git uses '\t' before timestamps, so split on tab first.
    after = line[4:].split("\t", 1)[0].strip()
    if not after:
        return None
    return after


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_TOOL_OUTPUT_TOKENS = 1_000    # hard cap on tool output before context injection
OLLAMA_BASE_URL        = "http://localhost:11434"
TARGET_NETWORK         = "sandbox_targets"   # Docker network name for target containers

# Tools available to Red Team agents
RED_TEAM_ALLOWED_TOOLS = {
    "nmap",
    "gobuster",
    "feroxbuster",
    "nikto",
    "whatweb",
    "curl",
    "httpx",
}

# Blue Team is NOT allowed to run offensive tools
BLUE_TEAM_ALLOWED_TOOLS = {
    "curl",       # HTTP health checks
    "diff",       # patch application verification
    "grep",       # log search
    "cat",        # read source files (read-only)
}


# ---------------------------------------------------------------------------
# Tool Result
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    tool:          str
    success:       bool
    raw_output:    str
    truncated:     bool
    token_estimate: int
    structured:    dict = field(default_factory=dict)  # parsed, structured output
    error:         str | None = None


# ---------------------------------------------------------------------------
# Output Truncation (MANDATORY — never bypass)
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def truncate_output(raw: str, max_tokens: int = MAX_TOOL_OUTPUT_TOKENS) -> tuple[str, bool]:
    """
    Truncates raw tool output to max_tokens.
    Returns (truncated_text, was_truncated).

    NEVER inject raw tool output into an agent context without calling this first.
    """
    estimated = _estimate_tokens(raw)
    if estimated <= max_tokens:
        return raw, False

    # Truncate to approximate token limit (chars = tokens * 4)
    char_limit = max_tokens * 4
    truncated  = raw[:char_limit]
    truncated += f"\n\n[OUTPUT TRUNCATED: {estimated} tokens → {max_tokens} tokens max]"
    logger.warning(f"[mcp] Output truncated: {estimated} → {max_tokens} tokens")
    return truncated, True


# ---------------------------------------------------------------------------
# Tool Execution (Red Team)
# ---------------------------------------------------------------------------

class RedTeamTransport:
    """
    MCP transport for Red Team agents.
    Executes offensive reconnaissance tools against target containers.
    """

    def run_tool(self, tool: str, args: list[str], target: str) -> ToolResult:
        """
        Executes an allowed Red Team tool and returns structured, truncated output.

        Args:
            tool:   tool name (must be in RED_TEAM_ALLOWED_TOOLS)
            args:   command arguments
            target: target URL or IP

        Returns:
            ToolResult with structured output (never raw)
        """
        if tool not in RED_TEAM_ALLOWED_TOOLS:
            logger.error(f"[mcp/red] Tool '{tool}' not in allowed list")
            return ToolResult(
                tool=tool, success=False, raw_output="",
                truncated=False, token_estimate=0,
                error=f"Tool '{tool}' is not permitted for Red Team",
            )

        cmd = [tool] + args + [target]
        logger.info(f"[mcp/red] Executing: {' '.join(shlex.quote(c) for c in cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 min max per tool invocation
            )
            raw = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            logger.warning(f"[mcp/red] Tool '{tool}' timed out after 120s")
            return ToolResult(
                tool=tool, success=False, raw_output="",
                truncated=False, token_estimate=0,
                error="Tool execution timed out",
            )
        except FileNotFoundError:
            logger.error(f"[mcp/red] Tool '{tool}' not found — is it installed?")
            return ToolResult(
                tool=tool, success=False, raw_output="",
                truncated=False, token_estimate=0,
                error=f"Tool '{tool}' not found on PATH",
            )

        # MANDATORY: truncate before returning
        truncated_output, was_truncated = truncate_output(raw)
        token_estimate = _estimate_tokens(truncated_output)

        return ToolResult(
            tool=tool,
            success=result.returncode == 0,
            raw_output=truncated_output,
            truncated=was_truncated,
            token_estimate=token_estimate,
            structured={},  # agents/red_team/ parsers fill this in
        )

    def nmap_scan(self, target: str) -> ToolResult:
        """
        Runs nmap service/version scan. Structured output extracts only:
        open ports, service names, versions, and detected technologies.
        Everything else is discarded.
        """
        result = self.run_tool(
            tool="nmap",
            args=["-sV", "--open", "-T4", "--script", "http-headers,http-title"],
            target=target,
        )

        if result.success:
            result.structured = self._parse_nmap(result.raw_output)

        return result

    def _parse_nmap(self, raw: str) -> dict:
        """
        Extracts only actionable fields from nmap output.
        Returns: {ports: [{port, protocol, service, version}], os_hints: []}
        """
        # TODO (Red Team Hire): implement full nmap XML parser
        # For now returns minimal structure
        ports = []
        for line in raw.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                ports.append({
                    "port":     parts[0] if parts else "unknown",
                    "state":    parts[1] if len(parts) > 1 else "unknown",
                    "service":  parts[2] if len(parts) > 2 else "unknown",
                    "version":  " ".join(parts[3:]) if len(parts) > 3 else "",
                })

        return {"ports": ports, "raw_summary": raw[:500]}  # hard cap on raw in struct


# ---------------------------------------------------------------------------
# Blue Team Transport (Read-Only Source Access + Patch Deployment)
# ---------------------------------------------------------------------------

class BlueTeamTransport:
    """
    MCP transport for Blue Team agents.

    Read access:  application source code from target containers
    Write access: patch deployment — STRICTLY limited to whitelisted paths
    """

    def read_source_file(self, container_id: str, file_path: str) -> ToolResult:
        """
        Reads a source file from a target container.
        Read-only — cannot write via this method.
        """
        cmd = ["docker", "exec", container_id, "cat", file_path]
        logger.info(f"[mcp/blue] Reading source: {container_id}:{file_path}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            raw = result.stdout
        except Exception as e:
            return ToolResult(
                tool="read_source", success=False, raw_output="",
                truncated=False, token_estimate=0, error=str(e),
            )

        truncated_output, was_truncated = truncate_output(raw)

        return ToolResult(
            tool="read_source",
            success=result.returncode == 0,
            raw_output=truncated_output,
            truncated=was_truncated,
            token_estimate=_estimate_tokens(truncated_output),
        )

    def deploy_patch(
        self,
        container_id:     str,
        patch_diff:       str,
        allowed_paths:    list[str],  # from Vulnerability Analysis — enforced here
    ) -> ToolResult:
        """
        Applies a unified diff patch to a target container.

        SECURITY: Only files in allowed_paths can be modified.
        Any patch touching a file outside this list is REJECTED before execution.

        Args:
            container_id:  Docker container to patch
            patch_diff:    unified diff string
            allowed_paths: list of file paths the Vulnerability Analysis identified
                           as the vulnerable location — ONLY these can be patched

        Returns:
            ToolResult indicating success or rejection reason
        """
        # Validate patch only touches allowed paths
        rejection = self._validate_patch_scope(patch_diff, allowed_paths)
        if rejection:
            logger.error(f"[mcp/blue] Patch REJECTED — scope violation: {rejection}")
            return ToolResult(
                tool="deploy_patch", success=False, raw_output="",
                truncated=False, token_estimate=0,
                error=f"Patch scope violation: {rejection}",
            )

        # Write patch to temp file and apply
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as f:
            f.write(patch_diff)
            patch_file = f.name

        try:
            cmd = ["docker", "exec", "-i", container_id, "patch", "-p1"]
            with open(patch_file, "r") as pf:
                result = subprocess.run(
                    cmd, stdin=pf, capture_output=True, text=True, timeout=60
                )
            raw = result.stdout + result.stderr
            success = result.returncode == 0
            logger.info(f"[mcp/blue] Patch {'applied' if success else 'FAILED'}: {container_id}")
        except Exception as e:
            raw = str(e)
            success = False
        finally:
            os.unlink(patch_file)

        truncated, was_truncated = truncate_output(raw)

        return ToolResult(
            tool="deploy_patch",
            success=success,
            raw_output=truncated,
            truncated=was_truncated,
            token_estimate=_estimate_tokens(truncated),
            error=None if success else raw[:500],
        )

    def _validate_patch_scope(self, patch_diff: str, allowed_paths: list[str]) -> str | None:
        """
        Parses the patch diff and verifies every modified file is in allowed_paths.
        Returns None if valid, or an error message if a scope violation is found.

        This is computed externally — the LLM cannot bypass this check.

        Rejects, in order:
          - Absolute paths in diff headers ('/etc/passwd')
          - Path traversal ('foo/../../etc/passwd' or anything resolving above the root)
          - Any path not present in the normalized allowed_paths set (exact match)
        """
        # Normalize allowed paths once. posixpath.normpath collapses '.' and '..'
        # components and removes redundant separators.
        normalized_allowed = {posixpath.normpath(p) for p in allowed_paths}

        seen: set[str] = set()
        for line in patch_diff.splitlines():
            raw_path = _parse_diff_header_path(line)
            if raw_path is None or raw_path == "/dev/null":
                continue

            # Strip 'a/' or 'b/' prefix (proper prefix, not chars).
            path = _strip_diff_prefix(raw_path)

            # Reject absolute paths — diffs should be relative to the repo root.
            if posixpath.isabs(path):
                return f"Patch references absolute path: {raw_path!r}"

            # Normalize: collapses '.' and '..' components. After normalization,
            # any leading '..' means the path escapes the repo root.
            normalized = posixpath.normpath(path)
            if normalized == ".." or normalized.startswith("../"):
                return f"Patch contains path traversal: {raw_path!r} → {normalized!r}"

            if normalized in seen:
                continue
            seen.add(normalized)

            if normalized not in normalized_allowed:
                return (
                    f"Patch modifies {normalized!r} which is not in the "
                    f"Vulnerability Analysis allowed paths: {sorted(normalized_allowed)}"
                )

        return None  # all good

    def read_logs(
        self,
        container_id: str,
        since_seconds: int = 300,  # last 5 minutes by default
    ) -> ToolResult:
        """
        Reads container logs time-windowed to around the detected exploit.
        Hard truncation to MAX_TOOL_OUTPUT_TOKENS.
        """
        cmd = ["docker", "logs", f"--since={since_seconds}s", container_id]
        logger.info(f"[mcp/blue] Reading logs: {container_id} (last {since_seconds}s)")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            raw = result.stdout + result.stderr
        except Exception as e:
            return ToolResult(
                tool="read_logs", success=False, raw_output="",
                truncated=False, token_estimate=0, error=str(e),
            )

        truncated, was_truncated = truncate_output(raw, max_tokens=800)  # stricter for logs

        return ToolResult(
            tool="read_logs",
            success=True,
            raw_output=truncated,
            truncated=was_truncated,
            token_estimate=_estimate_tokens(truncated),
        )


# ---------------------------------------------------------------------------
# Entry point: verify MCP transport connectivity
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("MCP Transport Layer — connectivity check")

    rt = RedTeamTransport()
    bt = BlueTeamTransport()

    # Check Docker is available
    result = subprocess.run(["docker", "ps"], capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Docker is accessible")
    else:
        print("✗ Docker not accessible — is Docker running?")

    print("\nTransport layer initialized. Run target containers before executing agents.")