"""
PhishGuard-AI — NLP Semantic Engine Service.
==============================================

Encapsulates the Hugging Face ``transformers`` pipeline wrapping a
fine-tuned BERT model.  The class follows the **Singleton** pattern:
a single instance is created during the FastAPI ``lifespan`` cold-start
and shared across all concurrent requests via ``app.state``.

Key Design Decisions
--------------------
- **Thread-offloading**: PyTorch inference is CPU-bound (or GPU-bound).
  Running it on the ASGI event loop would starve all concurrent I/O.
  We delegate each ``predict()`` call to a background thread via
  ``asyncio.to_thread()``, keeping the event loop responsive.

- **Model warm-up**: A dummy inference pass is executed at startup to
  JIT-compile any lazy CUDA kernels and pre-allocate memory.

Architecture Layer : Service / ML Inference
Thesis Reference   : §4.2 — BERT Inference Pipeline & Thread Isolation
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Final

import torch
from transformers import (  # type: ignore[import-untyped]
    AutoModelForSequenceClassification,
    AutoTokenizer,
    PreTrainedModel,
    PreTrainedTokenizerBase,
)

from core.config import BERT_MODEL_NAME, MALICIOUS_THRESHOLD

logger: Final[logging.Logger] = logging.getLogger("phishguard.nlp_engine")

# ==============================================================================
# Label Mapping
# ==============================================================================
# The ``textattack/bert-base-uncased-SST-2`` model emits:
#   label 0 → "NEGATIVE" (mapped to PHISHING in our domain)
#   label 1 → "POSITIVE" (mapped to LEGITIMATE)
_LABEL_MAP: Final[dict[int, str]] = {
    0: "LEGITIMATE",
    1: "PHISHING",
}


class SemanticEngine:
    """Singleton NLP engine backed by a HuggingFace BERT model.

    Lifecycle
    ---------
    1. ``__init__``   — Downloads/loads the model and tokenizer.
    2. ``warm_up``    — Runs a throwaway inference to prime caches.
    3. ``predict``    — Async method invoked per-request.
    4. ``shutdown``   — Explicit cleanup hook (releases VRAM if on GPU).
    """

    def __init__(self, model_name: str = BERT_MODEL_NAME) -> None:
        """Load the BERT model and tokenizer into memory.

        Parameters
        ----------
        model_name : str
            Hugging Face model identifier or local path.
        """
        logger.info("Loading BERT model '%s' …", model_name)

        self._device: Final[torch.device] = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        # ── Load tokenizer & model ──
        self._tokenizer: PreTrainedTokenizerBase = AutoTokenizer.from_pretrained(
            model_name
        )
        self._model: PreTrainedModel = (
            AutoModelForSequenceClassification.from_pretrained(model_name)
            .to(self._device)
            .eval()  # Inference mode — disables dropout.
        )

        logger.info(
            "BERT model loaded on device '%s' (params: %s).",
            self._device,
            f"{sum(p.numel() for p in self._model.parameters()):,}",
        )

    # ------------------------------------------------------------------
    # Warm-up
    # ------------------------------------------------------------------
    def warm_up(self) -> None:
        """Execute a dummy forward pass to pre-allocate tensors."""
        logger.info("Warming up BERT engine …")
        self._run_inference("PhishGuard warm-up probe.")
        logger.info("BERT engine warm-up complete.")

    # ------------------------------------------------------------------
    # Synchronous inference (runs on a worker thread)
    # ------------------------------------------------------------------
    def _run_inference(self, text: str) -> dict[str, Any]:
        """Run a **blocking** forward pass through the BERT model.

        This method MUST NOT be called directly on the event loop.
        It is designed to be invoked via ``asyncio.to_thread()``.

        Parameters
        ----------
        text : str
            Sanitized plaintext to classify.

        Returns
        -------
        dict
            ``{"label": str, "confidence": float, "is_malicious": bool}``
        """
        # ── Tokenize ──
        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding="max_length",
        ).to(self._device)

        # ── Inference (no gradient computation needed) ──
        with torch.no_grad():
            logits: torch.Tensor = self._model(**inputs).logits

        # ── Softmax → probabilities ──
        probabilities: torch.Tensor = torch.nn.functional.softmax(
            logits, dim=-1
        )
        predicted_class: int = int(torch.argmax(probabilities, dim=-1).item())
        confidence: float = round(
            float(probabilities[0][predicted_class].item()), 6
        )
        label: str = _LABEL_MAP.get(predicted_class, "UNKNOWN")
        is_malicious: bool = (
            predicted_class == 1 and confidence >= MALICIOUS_THRESHOLD
        )

        return {
            "label": label,
            "confidence": confidence,
            "is_malicious": is_malicious,
        }

    # ------------------------------------------------------------------
    # Async public API
    # ------------------------------------------------------------------
    async def predict(self, text: str) -> dict[str, Any]:
        """Classify the supplied text asynchronously.

        Offloads the CPU-bound PyTorch inference to a worker thread
        via ``asyncio.to_thread()`` so the ASGI event loop remains
        unblocked for concurrent I/O operations.

        Parameters
        ----------
        text : str
            Sanitized plaintext extracted from the DOM.

        Returns
        -------
        dict[str, Any]
            Classification result with ``label``, ``confidence``, and
            ``is_malicious`` keys.
        """
        logger.debug("Scheduling BERT inference on thread pool …")
        result: dict[str, Any] = await asyncio.to_thread(
            self._run_inference, text
        )
        logger.info(
            "BERT inference complete — label=%s, confidence=%.4f, malicious=%s",
            result["label"],
            result["confidence"],
            result["is_malicious"],
        )
        return result

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def shutdown(self) -> None:
        """Release model resources (useful for GPU VRAM reclamation)."""
        logger.info("Shutting down SemanticEngine — releasing resources.")
        del self._model
        del self._tokenizer
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
