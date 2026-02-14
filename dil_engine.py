#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# DIL Engine - Deterministic Integrity Layer
# Enterprise-Grade Audit & Governance Engine with SHA-256 Chaining
#
# Features:
#   - Immutable audit ledger with SHA-256 chaining
#   - Deterministic guardrails (amount/risk thresholds)
#   - Governance hash generation (HMAC-SHA256)
#   - Complete audit trail with timestamps
# ═══════════════════════════════════════════════════════════════════════════════

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("DILEngine")


# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

class Decision(Enum):
    """Audit decision outcomes"""
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    FLAGGED = "FLAGGED"


@dataclass
class AuditRequest:
    """Incoming audit request"""
    user_id: str
    amount: float
    ai_risk_score: float
    request_id: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if not self.request_id:
            self.request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class AuditRecord:
    """Immutable audit record"""
    request_id: str
    decision: str
    user_id: str
    amount: float
    ai_risk_score: float
    reason: str
    sha256_hash: str
    previous_hash: Optional[str]
    governance_hash: str
    timestamp: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class GuardrailViolation:
    """Guardrail violation details"""
    violated_rule: str
    threshold_value: float
    actual_value: float
    severity: str  # "SOFT", "HARD"


# ─────────────────────────────────────────────────────────────────────────────
# DIL ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DILEngine:
    """
    Deterministic Integrity Layer Engine
    
    Responsibilities:
    1. Apply deterministic guardrails (amount, risk_score)
    2. Maintain SHA-256 chaining (immutable ledger)
    3. Generate governance hashes (HMAC-SHA256)
    4. Provide complete audit trail
    
    Guardrail Rules:
    - HARD BLOCK: amount > $1,000,000
    - HARD BLOCK: risk_score < 0.5
    - SOFT FLAG: amount > $100,000 (requires review)
    - SOFT FLAG: risk_score between 0.5-0.7 (elevated risk)
    """

    # Guardrail thresholds
    AMOUNT_HARD_LIMIT = 1_000_000.0  # $1M hard block
    AMOUNT_SOFT_LIMIT = 100_000.0    # $100K requires review
    RISK_HARD_LIMIT = 0.5            # < 0.5 = unacceptable risk
    RISK_SOFT_LIMIT = 0.7            # 0.5-0.7 = elevated risk

    # Governance secret (in production: load from vault)
    GOVERNANCE_SECRET = b"DIL_GOVERNANCE_SECRET_2026"

    def __init__(self):
        """Initialize DIL Engine with empty ledger"""
        self.ledger: List[AuditRecord] = []
        self.previous_hash: Optional[str] = None
        logger.info("DILEngine initialized | SHA-256 chaining ready")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def process_audit(self, request: AuditRequest) -> Tuple[Decision, str, AuditRecord]:
        """
        Process an audit request through the complete DIL pipeline.
        
        Returns:
            Tuple of (Decision, Reason, AuditRecord)
        """
        logger.info(f"Processing audit: {request.request_id} | User: {request.user_id} | Amount: ${request.amount:,.2f}")

        # Step 1: Apply guardrails
        violations = self.check_guardrails(request.amount, request.ai_risk_score)

        # Step 2: Determine decision
        decision, reason = self._determine_decision(violations, request.amount, request.ai_risk_score)

        logger.info(f"Decision: {decision.value} | Reason: {reason}")

        # Step 3: Generate hashes
        record_dict = {
            "request_id": request.request_id,
            "user_id": request.user_id,
            "amount": request.amount,
            "ai_risk_score": request.ai_risk_score,
            "decision": decision.value,
            "reason": reason,
            "timestamp": request.timestamp
        }

        sha256_hash = self._generate_sha256(record_dict)
        governance_hash = self._generate_governance_hash(record_dict)

        # Step 4: Create and store audit record
        record = AuditRecord(
            request_id=request.request_id,
            decision=decision.value,
            user_id=request.user_id,
            amount=request.amount,
            ai_risk_score=request.ai_risk_score,
            reason=reason,
            sha256_hash=sha256_hash,
            previous_hash=self.previous_hash,
            governance_hash=governance_hash,
            timestamp=request.timestamp
        )

        self.ledger.append(record)
        self.previous_hash = sha256_hash

        logger.info(f"Record committed to ledger | Hash: {sha256_hash[:16]}... | Chain depth: {len(self.ledger)}")

        return decision, reason, record

    def check_guardrails(self, amount: float, risk_score: float) -> List[GuardrailViolation]:
        """
        Check transaction against deterministic guardrails.
        
        Returns list of violations (empty = all clear)
        """
        violations: List[GuardrailViolation] = []

        # Hard rule: Amount exceeds limit
        if amount > self.AMOUNT_HARD_LIMIT:
            violations.append(GuardrailViolation(
                violated_rule="AMOUNT_HARD_LIMIT",
                threshold_value=self.AMOUNT_HARD_LIMIT,
                actual_value=amount,
                severity="HARD"
            ))
            logger.warning(f"HARD violation: Amount ${amount:,.2f} exceeds limit ${self.AMOUNT_HARD_LIMIT:,.2f}")

        # Hard rule: Risk score too low
        if risk_score < self.RISK_HARD_LIMIT:
            violations.append(GuardrailViolation(
                violated_rule="RISK_HARD_LIMIT",
                threshold_value=self.RISK_HARD_LIMIT,
                actual_value=risk_score,
                severity="HARD"
            ))
            logger.warning(f"HARD violation: Risk score {risk_score:.2f} below acceptable {self.RISK_HARD_LIMIT}")

        # Soft rule: Amount requires review
        if self.AMOUNT_HARD_LIMIT >= amount > self.AMOUNT_SOFT_LIMIT:
            violations.append(GuardrailViolation(
                violated_rule="AMOUNT_SOFT_LIMIT",
                threshold_value=self.AMOUNT_SOFT_LIMIT,
                actual_value=amount,
                severity="SOFT"
            ))
            logger.info(f"SOFT violation: Amount ${amount:,.2f} in review range")

        # Soft rule: Risk score elevated
        if self.RISK_HARD_LIMIT <= risk_score < self.RISK_SOFT_LIMIT:
            violations.append(GuardrailViolation(
                violated_rule="RISK_SOFT_LIMIT",
                threshold_value=self.RISK_SOFT_LIMIT,
                actual_value=risk_score,
                severity="SOFT"
            ))
            logger.info(f"SOFT violation: Risk score {risk_score:.2f} in elevated range")

        return violations

    def get_ledger(self) -> List[Dict]:
        """Retrieve complete immutable ledger"""
        return [record.to_dict() for record in self.ledger]

    def get_ledger_size(self) -> int:
        """Get number of records in ledger"""
        return len(self.ledger)

    def get_current_hash(self) -> Optional[str]:
        """Get the current (most recent) SHA-256 hash"""
        return self.previous_hash

    def verify_chain_integrity(self) -> bool:
        """
        Verify the integrity of the SHA-256 chain.
        Each record should have previous_hash pointing to the prior record's hash.
        """
        if len(self.ledger) == 0:
            logger.info("Chain integrity check: Empty ledger (valid)")
            return True

        if len(self.ledger) == 1:
            is_valid = self.ledger[0].previous_hash is None
            logger.info(f"Chain integrity check: Single record (valid={is_valid})")
            return is_valid

        # Check each record's previous_hash matches the prior record's sha256_hash
        for i in range(1, len(self.ledger)):
            current_record = self.ledger[i]
            previous_record = self.ledger[i - 1]

            if current_record.previous_hash != previous_record.sha256_hash:
                logger.error(f"Chain integrity BROKEN at index {i}")
                return False

        logger.info(f"Chain integrity check: PASSED ({len(self.ledger)} records)")
        return True

    # ─────────────────────────────────────────────────────────────────────────
    # PRIVATE METHODS
    # ─────────────────────────────────────────────────────────────────────────

    def _determine_decision(self, violations: List[GuardrailViolation], amount: float, risk_score: float) -> Tuple[Decision, str]:
        """
        Determine decision based on violations.
        
        Logic:
        - Any HARD violation = BLOCKED
        - Any SOFT violation (no HARD) = FLAGGED
        - No violations = APPROVED
        """
        hard_violations = [v for v in violations if v.severity == "HARD"]
        soft_violations = [v for v in violations if v.severity == "SOFT"]

        if hard_violations:
            reasons = [f"{v.violated_rule} (threshold: {v.threshold_value}, actual: {v.actual_value})" 
                      for v in hard_violations]
            reason = f"BLOCKED: {'; '.join(reasons)}"
            return Decision.BLOCKED, reason

        if soft_violations:
            reasons = [f"{v.violated_rule} (threshold: {v.threshold_value}, actual: {v.actual_value})" 
                      for v in soft_violations]
            reason = f"FLAGGED: Requires review - {'; '.join(reasons)}"
            return Decision.FLAGGED, reason

        reason = f"APPROVED: All guardrails passed (Amount: ${amount:,.2f}, Risk: {risk_score:.2f})"
        return Decision.APPROVED, reason

    def _generate_sha256(self, data: Dict) -> str:
        """
        Generate SHA-256 hash of audit record.
        Deterministic: same input always produces same hash.
        """
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def _generate_governance_hash(self, data: Dict) -> str:
        """
        Generate HMAC-SHA256 governance hash.
        Ensures authenticity and integrity.
        """
        json_str = json.dumps(data, sort_keys=True)
        return hmac.new(
            self.GOVERNANCE_SECRET,
            json_str.encode(),
            hashlib.sha256
        ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON INSTANCE
# ─────────────────────────────────────────────────────────────────────────────

# Global DIL Engine instance (shared across requests)
_engine_instance: Optional[DILEngine] = None


def get_dil_engine() -> DILEngine:
    """Get or create the global DIL Engine instance"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DILEngine()
    return _engine_instance


if __name__ == "__main__":
    # Quick test
    engine = DILEngine()

    # Test 1: Approved transaction
    req1 = AuditRequest(user_id="user-001", amount=5000.0, ai_risk_score=0.85)
    decision1, reason1, record1 = engine.process_audit(req1)
    print(f"\nTest 1: {decision1.value} - {reason1}")
    print(f"Hash: {record1.sha256_hash}")

    # Test 2: Flagged transaction
    req2 = AuditRequest(user_id="user-002", amount=150_000.0, ai_risk_score=0.65)
    decision2, reason2, record2 = engine.process_audit(req2)
    print(f"\nTest 2: {decision2.value} - {reason2}")
    print(f"Hash: {record2.sha256_hash}")

    # Test 3: Blocked transaction
    req3 = AuditRequest(user_id="user-003", amount=2_000_000.0, ai_risk_score=0.3)
    decision3, reason3, record3 = engine.process_audit(req3)
    print(f"\nTest 3: {decision3.value} - {reason3}")
    print(f"Hash: {record3.sha256_hash}")

    # Verify chain
    print(f"\nLedger size: {engine.get_ledger_size()}")
    print(f"Chain integrity: {engine.verify_chain_integrity()}")
    print(f"Current hash: {engine.get_current_hash()}")
