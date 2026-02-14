import asyncio
import json
from brain.risk_scorer import calculate_risk
from brain.ledger import log_decision

async def auditor_explainer(agent_output: dict, context_data: dict) -> str:
    """
    Mock secondary 'Auditor Model' for generating justification.
    """
    # In a real scenario, this would call GPT-4o-mini / Haiku
    await asyncio.sleep(0.1) # Simulate network latency
    action = agent_output.get('proposed_action', 'unknown action')
    return f"The action '{action}' is justified as it aligns with the provided context and safety protocols."

async def run_dil_orchestration(prompt: str, context_data: dict, agent_output: dict):
    print("--- [Decision Intelligence Layer] Intercepting Output ---")
    
    # Prepare the initial decision object for the Ledger
    decision_payload = {
        "prompt": prompt,
        "context": context_data,
        "proposed_action": agent_output.get('proposed_action'),
        "metadata": agent_output.get('metadata')
    }
    
    # 1. RISK SCORER (Run analysis)
    risk_assessment = calculate_risk(agent_output, context_data)
    decision_payload["risk_assessment"] = risk_assessment
    
    # 2 & 3. EXPLAINER and LEDGER (Run concurrently)
    # Note: Ledger needs the risk score for its fingerprint, so we run it after RiskScorer
    # as per requirements, but concurrently with the Explainer and potentially other steps.
    
    print(f"Calculating Risk: {risk_assessment['RiskScore']} - {risk_assessment['RiskReasoning']}")
    
    # Run Ledger and Explainer in parallel
    explainer_task = asyncio.create_task(auditor_explainer(agent_output, context_data))
    ledger_task = asyncio.create_task(log_decision(decision_payload))
    
    justification, ledger_success = await asyncio.gather(explainer_task, ledger_task)
    
    decision_payload["justification"] = justification
    decision_payload["ledger_confirmed"] = ledger_success
    
    # 4. GATEKEEPER logic
    risk_score = risk_assessment['RiskScore']
    is_certified = False
    status = "REJECTED/WAITING"
    
    if not ledger_success:
        status = "FAILED: Ledger write unsuccessful. Integrity check required."
    elif risk_score > 0.7:
        status = "HITL_PAUSE: Risk score above threshold (0.7). Human intervention required."
    else:
        is_certified = True
        status = "CERTIFIED: Decision passed all safety and logging protocols."
    
    certified_decision = {
        "status": status,
        "is_certified": is_certified,
        "decision_id": decision_payload.get('metadata', {}).get('request_id', 'unknown'),
        "risk_score": risk_score,
        "decision_payload": decision_payload
    }
    
    return certified_decision

async def main():
    # Use-case 1: Low Risk (Fintech)
    print("\n--- TEST CASE 1: Low Risk Fintech ---")
    prompt_1 = "Transfer $100 to Alice."
    context_1 = {
        "context_completeness": 0.95,
        "domain": "fintech",
        "transaction_value": 100
    }
    agent_output_1 = {
        "proposed_action": "Execute transfer of $100 to account_id: 12345",
        "confidence_score": 0.98,
        "metadata": {"request_id": "TX-1001"}
    }
    
    result_1 = await run_dil_orchestration(prompt_1, context_1, agent_output_1)
    print(json.dumps(result_1, indent=2))

    # Use-case 2: High Risk (Healthcare - Low Context + Low Confidence)
    print("\n--- TEST CASE 2: High Risk Healthcare ---")
    prompt_2 = "Adjust dosage of medication."
    context_2 = {
        "context_completeness": 0.2, # Very low context
        "domain": "health",
        "patient_safety_impact": 0.9
    }
    agent_output_2 = {
        "proposed_action": "Increase dosage by 50mg",
        "confidence_score": 0.6,
        "metadata": {"request_id": "RX-2002"}
    }
    
    result_2 = await run_dil_orchestration(prompt_2, context_2, agent_output_2)
    print(json.dumps(result_2, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
