import re
from dataclasses import dataclass
from typing import Optional, List
from Guardrails.implement_llm import call_gemini_api


@dataclass
class Guardrails:
    allowed: bool
    stage: str
    reason: str = ""
    response: Optional[str] = None


ATTACK_PATTERNS = [
    "ignore", "previous", "prior", "rules", "prompt", "forget", "instructions", "context"
]

INDIRECT_PROMPT_PATTERNS = {
    "ignore_previous": r"(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions|directions|rules)",
    "system_override": r"(system\s+override|new\s+instructions:|override\s+default\s+behavior)",
    "role_hijack": r"(you\s+are\s+now|act\s+as\s+an?)\s+(unrestricted|unfiltered|malicious|evil)",
    "hidden_markdown_exfil": r"!\[.*?\]\(https?://[^\s)]+\?[^\s)]*?\)",
    "xml_tag_injection": r"<\s*(system|instruction|prompt|override)\s*>",
}

SENSITIVITY_PATTERNS = [
    r"system prompt", r"api[-_]?key", r"secret", r"password", r"token", r"private key", 
    r"confidential", r"credentials", r"authorization", r"access[-_]?key",
]

ALLOWED_TOPICS_KEYWORDS = [
    "weather", "news", "sports", "entertainment", "technology", "health", "science", "education", "travel", 
    "finance", "business", "politics", "history", "culture", "art", "music", "literature", "philosophy", 
    "psychology", "sociology", "environment", "nature", "animals", "hi", "hello", "hey",
    "pm", "prime minister", "india", "government", "minister" 
]

BLOCKED_TOOL_CALLS = {
    "send_payment", "delete_account", "access_sensitive_data", "modify_system_settings", "execute_remote_code",
}

HIGH_RISK_TOOLS = {
    "transfer_funds", "update_database", "send_bulk_email"
}


def input_rail(user_text: str) -> Guardrails:
    for pattern in ATTACK_PATTERNS:
        if re.search(pattern, user_text, re.IGNORECASE):
            return Guardrails(
                allowed=False,
                stage="Input Guardrail (Injection Detected)",
                reason=f"Directive pattern matched: {pattern}"
            )
    return Guardrails(allowed=True, stage="Input Allowed", reason="No input threat detected.")


def context_rail(system_prompt: str) -> Guardrails:
    for name, pattern in INDIRECT_PROMPT_PATTERNS.items():
        if re.search(pattern, system_prompt, re.IGNORECASE):
            return Guardrails(
                allowed=False,
                stage="Context Guardrail (Prompt Tampering)",
                reason=f"Suspicious pattern found in context/system prompt: {name}"
            )
    return Guardrails(allowed=True, stage="Context Allowed", reason="Context prompt is secure.")


def business_rule_rail(user_text: str) -> Guardrails:
    is_on_topic = any(keyword in user_text.lower() for keyword in ALLOWED_TOPICS_KEYWORDS)
    if not is_on_topic:
        return Guardrails(
            allowed=False,
            stage="Business Rule Guardrail (Off-Topic)",
            reason="Input violates domain/business topic restrictions."
        )
    return Guardrails(allowed=True, stage="Business Rule Allowed", reason="Input follows business guidelines.")


def execution_rail(requested_tool_call: Optional[str]) -> Guardrails:
    if requested_tool_call and requested_tool_call in BLOCKED_TOOL_CALLS:
        return Guardrails(
            allowed=False,
            stage="Tool Guardrail (Blocked Call)",
            reason=f"Forbidden tool execution attempted: {requested_tool_call}"
        )
    return Guardrails(allowed=True, stage="Tool Execution Allowed", reason="No blocked tool calls.")

def hitl_rail(requested_tool_call: Optional[str]) -> Guardrails:
    if requested_tool_call and requested_tool_call in HIGH_RISK_TOOLS:
        return Guardrails(
            allowed=False,
            stage="Human-in-the-Loop (HITL) Approval Required",
            reason=f"Tool '{requested_tool_call}' requires manual supervisor approval.",
            response="Execution paused: Awaiting human review."
        )
    return Guardrails(allowed=True, stage="HITL Passed", reason="No manual approval needed.")


def output_rail(model_output: str) -> Guardrails:
    for pattern in SENSITIVITY_PATTERNS:
        if re.search(pattern, model_output, re.IGNORECASE):
            return Guardrails(
                allowed=False,
                stage="Output Guardrail (Sensitive Data Leak)",
                reason=f"Restricted sensitive pattern found in output: {pattern}"
            )
    return Guardrails(allowed=True, stage="Output Allowed", reason="Output is safe and clean.")


# Complete Guardrails Pipeline
def run_guardrails_pipeline(user_text: str, system_prompt: str, requested_tool_call: Optional[str] = None):
    res_input = input_rail(user_text)
    if not res_input.allowed:
        return f"Blocked at [{res_input.stage}], Reason: {res_input.reason}"

    res_context = context_rail(system_prompt)
    if not res_context.allowed:
        return f"Blocked at [{res_context.stage}], Reason: {res_context.reason}"

    res_business = business_rule_rail(user_text)
    if not res_business.allowed:
        return f"Blocked at [{res_business.stage}], Reason: {res_business.reason}"

    if requested_tool_call:
        res_tool = execution_rail(requested_tool_call)
        if not res_tool.allowed:
            return f"Blocked at [{res_tool.stage}], Reason: {res_tool.reason}"

        res_hitl = hitl_rail(requested_tool_call)
        if not res_hitl.allowed:
            return f"Paused/Blocked at [{res_hitl.stage}], Reason: {res_hitl.reason}"

    llm_response = call_gemini_api(user_text, system_instructions=system_prompt)

    res_output = output_rail(llm_response)
    if not res_output.allowed:
        return f"Blocked at [{res_output.stage}], Reason: {res_output.reason}"
    
    return res_output.response if res_output.response else llm_response