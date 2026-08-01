"""Orchestration for the intentionally weak starter guardrail."""

from __future__ import annotations

from collections.abc import Sequence

from common import Action, GuardrailDecision, GuardrailRequest, ReasonCode, Route
from guardrail.detectors import Detector, GenerateAbuseDetector,OrderedKeywordDetector, Signal
from guardrail.normalization import normalize_text
from guardrail.policy import StarterPolicy
from guardrail.quoted_evidence import QuotedEvidenceDetector
from guardrail.vector_detector import create_starter_prototype_detector


class StarterGuardrail:
    """Normalize, flatten, detect, and fuse a request."""

    def __init__(
        self,
        detectors: Sequence[Detector] | None = None,
        policy: StarterPolicy | None = None,
    ) -> None:
        self._detectors = (
            tuple(detectors)
            if detectors is not None
            else (
                OrderedKeywordDetector(),
                GenerateAbuseDetector(),
                create_starter_prototype_detector(),
            )
        )
        self._policy = policy or StarterPolicy()
        self._quoted_evidence = QuotedEvidenceDetector()

    def check(self, request: GuardrailRequest) -> GuardrailDecision:
        context = request.context

        if context.requested_operation not in context.allowed_operations:
            return GuardrailDecision(
                action=Action.BLOCK,
                reason_code=ReasonCode.UNAUTHORIZED_ACTION,
                policy_version=self._policy.policy_version,
            )

        active_text = normalize_text(request.message).control_stripped

        signals: list[Signal] = []
        for detector in self._detectors:
            signal = detector.detect(active_text)
            if signal is not None:
                signals.append(signal)

        if signals:
            return self._policy.decide(signals, context.route)

        if context.route == Route.REPORT and request.evidence:
            quoted_signal = self._quoted_evidence.detect(request.evidence)

            if quoted_signal is not None:
                return GuardrailDecision(
                    action=quoted_signal.action,
                    reason_code=quoted_signal.reason_code,
                    policy_version=self._policy.policy_version,
                )

        return self._policy.decide((), context.route)
