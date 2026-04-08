# Deep Memory Plugin

Reasoning-based memory system inspired by [Honcho](https://docs.honcho.dev). Provides structured reasoning over conversations, entity tracking, and hybrid semantic + keyword search — all running locally with zero external hosting.

## Install

```bash
pip install hermes-agent[deep-memory]
# or standalone:
pip install deep-memory
```

For semantic search (recommended):
```bash
pip install sentence-transformers sqlite-vec
```

## Tools

| Tool | Description |
|------|-------------|
| `recall` | Search deep memory for insights — hybrid semantic + keyword search |
| `learn` | Store structured insights (explicit, deductive, inductive, abductive) |
| `entities` | Manage entity profiles (people, projects, concepts) |

## How It Works

### Automatic Post-Session Reasoning
After each conversation, deep-memory automatically:
1. Extracts structured insights from the conversation
2. Classifies them (explicit → deductive → inductive → abductive)
3. Stores with embeddings for future semantic recall
4. Updates entity profiles mentioned in the conversation

### System Prompt Injection
Each turn, relevant deep memory context is injected into the system prompt:
- Entity profile cards for known participants
- High-confidence insights from past sessions

### Embedding Auto-Config
Deep-memory automatically detects the best embedding backend:

| Priority | Backend | Condition | Model | Dimension |
|----------|---------|-----------|-------|-----------|
| 1 | Config | `deep_memory.embedding_backend` set | — | — |
| 2 | Local | `sentence-transformers` installed | all-MiniLM-L6-v2 | 384 |
| 3 | OpenAI | `OPENAI_API_KEY` set | text-embedding-3-small | 1536 |
| 4 | FTS-only | Fallback | — | — |

## Configuration (Optional)

```yaml
# ~/.hermes/config.yaml
deep_memory:
  embedding_backend: auto  # auto | local | openai | none
```

No configuration is required — auto-detection handles everything.

## Data Storage

All data lives in a single SQLite file:
```
~/.hermes/deep_memory/memory.db
```

Tables:
- `entities` — People, projects, concepts (equivalent to Honcho Peers)
- `conclusions` — Structured insights with embeddings (equivalent to Honcho Representations)
- `summaries` — Compressed session digests

## Diagnostics

```python
from deep_memory.embedding import diagnose
print(diagnose())
# {'sentence_transformers_available': True, 'openai_api_key_set': False,
#  'sqlite_vec_available': True, 'configured_backend': None, 'auto_detected': 'local'}
```

## Source

- Repository: [github.com/RichardHojunJang/deep-memory](https://github.com/RichardHojunJang/deep-memory)
- License: AGPL-3.0 (same as Hermes Agent)
