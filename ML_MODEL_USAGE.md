# LogCentry ML Model Usage Guide

This document explains exactly where Machine Learning is used in LogCentry today, what algorithm/model is used, how it works, how it differs from rule-based log segregation, and what performance/quality impact to expect.

---

## 1) Executive Summary

LogCentry currently uses ML in the **RAG retrieval quality stage** (context re-ranking), not as a standalone binary classifier for normal vs abnormal logs.

- **ML model in use:** `cross-encoder/ms-marco-MiniLM-L6-v2`
- **ML role:** Re-rank retrieved security context (MITRE/CVE/custom docs) so the LLM receives the most semantically relevant evidence.
- **Not the current ML role:** direct classification of logs into normal vs abnormal.
- **Current normal/abnormal gating:** heuristic selection in dashboard + backend suspicious-term fast-path.

So the current architecture is:

1. Heuristic/rule gating selects which logs to analyze.
2. RAG retrieves candidate context from ChromaDB.
3. Cross-Encoder ML re-ranks that context.
4. LLM produces final security assessment.

---

## 2) Where ML Is Used (Exact Code Paths)

### 2.1 Model loading and lifecycle

- File: `src/logcentry/rag/retriever.py`
- Function: `_load_cross_encoder(model_name)`
- Behavior:
  - Lazy loads `sentence_transformers.CrossEncoder`
  - Avoids startup penalty when RAG is not used
  - Gracefully disables reranking if model load fails

### 2.2 Two-stage retrieval with ML reranking

- File: `src/logcentry/rag/retriever.py`
- Method: `ContextRetriever.retrieve(...)`
- Behavior:
  1. **Stage 1 (Bi-Encoder / Vector Search):**
     - Uses embeddings + ChromaDB to fetch candidate contexts
     - Candidate pool expands to `top_k * candidate_multiplier`
     - Candidate pool is hard-capped by `rag_reranker_max_candidates`
  2. **Stage 2 (Cross-Encoder / ML Re-rank):**
     - Builds `(query, context)` pairs
     - Calls `cross_encoder.predict(pairs)`
     - Sorts by score descending and takes top `k`

### 2.3 Where this ML output is consumed

- File: `src/logcentry/api/server.py`
- Endpoint: `POST /api/v1/analyze`
- Behavior:
  - For `use_rag=true`, calls retriever (`retrieve_for_logs`) to get context
  - Context goes into `ThreatAnalyzer.analyze(...)`
  - LLM analysis is grounded by reranked RAG evidence

---

## 3) What Algorithm Is This?

## Algorithm: Transformer Cross-Encoder Re-ranking

### Model

- **Model:** `cross-encoder/ms-marco-MiniLM-L6-v2`
- **Family:** Sentence Transformers Cross-Encoder
- **Input format (conceptual):** `[CLS] query [SEP] candidate_context [SEP]`
- **Output:** scalar relevance score per pair

### Why this differs from vector-only retrieval

- **Vector-only (bi-encoder) retrieval** embeds query/doc independently and compares vectors.
- **Cross-encoder** jointly attends to query+doc token interactions and usually gives better ranking quality for final top-N context.

This is why the model is used as a **reranker**, not as primary retrieval.

---

## 4) What the ML Model Is Doing (And Not Doing)

### It IS doing

- Ranking candidate knowledge chunks by semantic relevance to the log query.
- Reducing context noise before LLM prompt assembly.
- Improving evidence quality for MITRE/CVE mapping and remediation suggestions.

### It is NOT doing (currently)

- Direct anomaly detection on raw logs.
- Direct benign/malicious classification labels.
- Replacing rule-based SIEM correlation.

---

## 5) Then How Normal vs Abnormal Is Segregated Today?

Current segregation is hybrid and mostly rule/heuristic-driven:

1. **Dashboard selection heuristic** (`src/logcentry/dashboard/templates/index.html`)
   - Scores logs by level + suspicious keywords/signals.
   - Sends selected `log_ids` to analyze endpoint.
   - Falls back to a small recent slice for normal-only traffic.

2. **Backend benign fast-path** (`src/logcentry/api/server.py`)
   - Checks suspicious terms in selected logs.
   - If no suspicious terms, returns low-severity benign response quickly.

3. **Full AI path for suspicious logs**
   - RAG retrieval (+ cross-encoder reranking if enabled)
   - LLM threat analysis

---

## 6) Why Reranking Is Useful Even If Segregation Already Exists

Segregation and reranking solve different problems:

- **Segregation answers:** “Should this log batch go to deeper analysis?”
- **Reranking answers:** “Given we are analyzing, which evidence should the LLM trust most?”

Without reranking, even correctly selected suspicious logs may get weak/irrelevant context, leading to:

- lower explanation quality,
- higher chance of noisy mitigation output,
- weaker MITRE/CVE grounding.

With reranking, LLM sees better evidence and can produce more precise SIEM-style output.

---

## 7) Stats: With vs Without ML Reranking

Important: There are two categories below.

- **A) Expected/benchmark-level stats** (from common MS MARCO style reranking behavior)
- **B) Current project runtime observations** (what we measured while debugging this repo)

### 7.1 A) Expected retrieval-quality impact (reranker OFF vs ON)

These are typical ranges from public reranking behavior and should be treated as directional expectations, not guaranteed values for every environment.

| Metric | Vector-only (No reranker) | Two-stage with Cross-Encoder |
|---|---:|---:|
| MRR@10 (typical range) | ~0.16–0.20 | ~0.35–0.40 |
| Retrieval latency | ~10–20ms | ~40–70ms total (vector + rerank) |
| Final context precision | Variable | Higher, more semantically aligned |

### 7.2 B) Current project runtime observations

From recent local validation in this repository:

- Benign fast-path (normal log with selected `log_id`) returned in ~0.03s.
- Full LLM path can still take tens of seconds depending on provider/network load.
- Timeouts are now guarded by:
  - `LOGCENTRY_RAG_RETRIEVAL_TIMEOUT_SECONDS`
  - `LOGCENTRY_ANALYSIS_REQUEST_TIMEOUT_SECONDS`

So reranking improves context quality, but overall response time is still dominated by LLM/provider conditions when full analysis runs.

---

## 8) Configuration That Controls ML Behavior

In `src/logcentry/config.py` and `.env`:

- `LOGCENTRY_RAG_RERANKER_ENABLED` (default: true)
- `LOGCENTRY_RAG_RERANKER_MODEL` (default: `cross-encoder/ms-marco-MiniLM-L6-v2`)
- `LOGCENTRY_RAG_RERANKER_CANDIDATE_MULTIPLIER` (default: 3)
- `LOGCENTRY_RAG_RERANKER_MAX_CANDIDATES` (default: 30)
- `LOGCENTRY_RAG_RETRIEVAL_TIMEOUT_SECONDS` (default: 15)
- `LOGCENTRY_ANALYSIS_REQUEST_TIMEOUT_SECONDS` (default: 45)

### Practical tuning guidance

- If latency is high:
  - reduce `candidate_multiplier` or `max_candidates`
  - keep reranker enabled for quality, but with tighter candidate cap
- If quality seems weak:
  - increase `max_candidates` moderately
  - consider a stronger reranker model if infra allows

---

## 9) Validation and Tests

Reranker behavior is tested in `tests/test_rag.py`:

- Reranker can reorder candidate rankings correctly.
- Lazy loading behavior is validated.
- Failure fallback disables reranker and continues vector-only mode.
- Candidate pool capping logic is validated.

These tests verify reranking mechanics and resilience; they do not yet measure dataset-level detection accuracy for production traffic.

---

## 10) Limitations and Current Scope

Current scope:

- ML is a **retrieval reranker**, not a full anomaly classifier.
- Normal vs abnormal segregation currently includes heuristic/rule stages.

If your goal is full ML-based segregation, next step is to add a dedicated classifier/anomaly model before analysis routing.

---

## 11) Recommended Next Step (If You Want Full ML Segregation)

Add a dedicated “ML Risk Scoring” stage before `/api/v1/analyze`:

1. Build feature schema from log text + metadata + temporal behavior.
2. Score each log with a classifier/anomaly model.
3. Route high-risk logs to full RAG+LLM.
4. Keep benign fast-path for very low scores.
5. Log model score + reason tags for explainability in UI.

This gives true ML-based segregation while retaining reranker benefits for evidence quality.

---

## 12) Final Takeaway

- Yes, ML is used now.
- It is used for **RAG context reranking**, which materially improves context quality for LLM analysis.
- It is complementary to your existing rule/heuristic segregation, not a duplicate.
- For end-to-end ML segregation, you need one additional dedicated classifier stage.
