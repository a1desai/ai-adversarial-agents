# =============================================================================
# agents/blue_team/Dockerfile
# OWNER: Blue Team Hire / Infra Hire
# PURPOSE: Container image for the Blue Team LangGraph agent pipeline.
#
# Shares the same base, layer layout, and env contract as the Red Team image
# (agents/red_team/Dockerfile, #31) so both stacks rebuild identically.
#
# Build context is the repo root (docker-compose.agents.yml: context: .)
# so all paths below are relative to the repo root.
#
# Ollama runs on the HOST — reached via host.docker.internal:11434.
# ChromaDB storage is bind-mounted from .chromadb/ on the host.
# =============================================================================

FROM python:3.11-slim

# Keeps Python from buffering stdout/stderr — logs appear immediately
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install dependencies first (separate layer — cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy source — docker-compose.agents.yml bind-mounts agents/ and prompts/
# at runtime (read-only), but we copy them here so the image is self-contained
# for one-off runs and CI.
COPY agents/ ./agents/
COPY prompts/ ./prompts/
COPY dummy_data/ ./dummy_data/
COPY knowledge_base/ ./knowledge_base/
COPY evaluation/ ./evaluation/
COPY pyproject.toml .

# Runtime env vars — overridden by docker-compose.agents.yml environment block
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434 \
    CHROMADB_PATH=/app/.chromadb \
    LOG_LEVEL=INFO

# Smoke check — confirms all Blue Team agent modules import cleanly at build time
RUN python -c "\
from agents.blue_team.supervisor import create_blue_team_graph; \
from agents.blue_team.log_analysis_agent import LogAnalysisAgent; \
from agents.blue_team.root_cause_agent import RootCauseAgent; \
from agents.blue_team.patch_generation_agent import PatchGenerationAgent; \
from agents.blue_team.patch_validation_agent import PatchValidationAgent; \
print('imports ok')"

CMD ["python", "-m", "agents.blue_team.supervisor"]
