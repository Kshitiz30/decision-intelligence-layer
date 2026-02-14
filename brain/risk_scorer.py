import json

def calculate_risk(agent_output: dict, context_data: dict) -> dict:
    """
    Analyzes 'Confidence Score' vs 'Context Completeness' and domain-specific weights.
    Returns a dict with 'RiskScore' (0-1) and 'RiskReasoning'.
    """
    confidence = agent_output.get('confidence_score', 0.5)
    completeness = context_data.get('context_completeness', 1.0)
    domain = context_data.get('domain', 'general')
    
    # Base risk starts with the inverse of confidence
    base_risk = 1.0 - confidence
    
    # Increase risk if context is incomplete
    # If agent is 99% sure but context is 0% complete, risk should spike.
    context_spike = (1.0 - completeness) * 0.5
    
    risk_score = base_risk + context_spike
    
    reasoning_parts = []
    if confidence < 0.7:
        reasoning_parts.append(f"Low confidence score ({confidence:.2f})")
    if completeness < 0.5:
        reasoning_parts.append(f"Severely incomplete context ({completeness:.2f})")
        
    # Sector-Specific Weights
    if domain == 'fintech':
        tx_value = context_data.get('transaction_value', 0)
        # Weight transaction value: e.g., > $10,000 adds significant risk
        val_impact = min(tx_value / 20000, 0.4)
        risk_score += val_impact
        if val_impact > 0.1:
            reasoning_parts.append(f"High transaction value in fintech domain (${tx_value})")
            
    elif domain == 'health':
        safety_impact = context_data.get('patient_safety_impact', 0) # 0 to 1
        # Heavily weight patient safety
        safety_weight = safety_impact * 0.6
        risk_score += safety_weight
        if safety_impact > 0.3:
            reasoning_parts.append(f"High patient safety impact in healthcare domain")
            
    # Normalize risk score between 0.0 and 1.0
    final_score = max(0.0, min(1.0, risk_score))
    
    reasoning = "; ".join(reasoning_parts) if reasoning_parts else "All parameters within safe thresholds."
    
    return {
        "RiskScore": round(final_score, 3),
        "RiskReasoning": reasoning
    }
