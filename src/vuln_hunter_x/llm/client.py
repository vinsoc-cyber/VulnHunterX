"""LLM client abstraction for OpenAI and Ollama via LiteLLM."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import litellm

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.llm.prompts import PromptBuilder


class LLMClient:
    """
    Unified LLM client using LiteLLM for OpenAI and Ollama.
    
    Uses LLM mode only (multi-turn with context expansion).
    """
    
    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        temperature: float = 0.2,
        max_tokens: int = 1500,
    ):
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.prompt_builder = PromptBuilder()
        
        # Configure Ollama base URL if provided
        if provider == "ollama":
            ollama_base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
            os.environ["OLLAMA_API_BASE"] = ollama_base
    
    def analyze(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        context_provider: ContextProvider | None = None,
        max_iterations: int = 3,
        verbose: bool = False,
        log_file: Any | None = None,
        quiet: bool = False,
    ) -> Verdict:
        """
        Analyze a finding and return a verdict.
        
        Uses multi-turn conversation with context expansion (LLM mode).
        
        Args:
            finding: The CodeQL finding to analyze
            context: Code context around the finding
            questions: Guided questions for the rule
            func_name: Name of the function containing the finding
            context_provider: Provider for additional context (multi-turn)
            max_iterations: Maximum conversation rounds
            verbose: Show detailed output
            log_file: Optional file to log conversations
            quiet: Suppress output
            
        Returns:
            Verdict with the analysis result
        """
        user_prompt = self.prompt_builder.build_user_prompt(
            finding, context, questions, func_name
        )
        messages = [
            {"role": "system", "content": self.prompt_builder.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        # Print initial prompts in verbose mode
        if verbose:
            print("\n    === SYSTEM PROMPT ===")
            sys_prompt = self.prompt_builder.system_prompt
            if len(sys_prompt) > 1000:
                print(f"    [System prompt: {len(sys_prompt)} chars, showing first 1000...]")
                print(f"    {sys_prompt[:1000]}...")
            else:
                print(f"    {sys_prompt}")
            print("    === END SYSTEM PROMPT ===\n")
        
        # Log initial prompt
        if log_file:
            log_file.write(f"## Finding: {finding.rule_id}\n\n")
            log_file.write(f"- **File**: `{finding.file}:{finding.start_line}`\n")
            log_file.write(f"- **Message**: {finding.message}\n")
            log_file.write(f"- **Function**: `{func_name}`\n\n")
            log_file.write(f"### System Prompt\n\n```\n{self.prompt_builder.system_prompt}\n```\n\n")
            log_file.write(f"### User Prompt\n\n```\n{user_prompt}\n```\n\n")
        
        start_time = time.time()
        iterations = 0
        all_raw_responses: list[str] = []
        
        while iterations < max_iterations:
            iterations += 1
            
            if verbose:
                print(f"\n    [Iteration {iterations}/{max_iterations}] Sending request to LLM...")
                # Print the request being sent
                print("\n    === LLM REQUEST ===")
                last_user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
                # Show truncated version for readability
                if len(last_user_msg) > 2000:
                    print(f"    [User message: {len(last_user_msg)} chars, showing first 2000...]")
                    print(f"    {last_user_msg[:2000]}...")
                else:
                    print(f"    {last_user_msg}")
                print("    === END REQUEST ===\n")
            elif not quiet:
                print("    Calling LLM...", end="", flush=True)
            
            try:
                model = self.model
                api_base = None
                if self.provider == "openai":
                    api_base = (os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or "").strip()
                    api_base = api_base.rstrip("/") if api_base else None
                    if api_base and not model.startswith("openai/"):
                        model = "openai/" + model
                kwargs = {
                    "model": model,
                    "messages": messages,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                }
                if api_base:
                    kwargs["api_base"] = api_base
                response = litellm.completion(**kwargs)
                if not response.choices:
                    raise ValueError("LLM returned empty choices list")
                raw_response = response.choices[0].message.content or ""
                all_raw_responses.append(raw_response)
                
                if not verbose and not quiet:
                    print(f" done ({len(raw_response)} chars)")
                
                # Log response
                if log_file:
                    log_file.write(f"### LLM Response (Iteration {iterations})\n\n")
                    log_file.write(f"```json\n{raw_response}\n```\n\n")
                
                if verbose:
                    print(f"    === LLM RESPONSE ({len(raw_response)} chars) ===")
                    print(f"    {raw_response}")
                    print("    === END RESPONSE ===\n")
                
                # Parse response
                parsed = self._parse_response(raw_response)
                verdict = parsed.get("verdict", "Needs More Data")
                context_needed = parsed.get("context_needed", [])
                
                if verbose:
                    print(f"    Parsed: verdict={verdict}, confidence={parsed.get('confidence', 'Low')}")
                
                # Final verdict or no context expansion
                if verdict != "Needs More Data" or not context_needed or not context_provider:
                    elapsed = time.time() - start_time
                    
                    if log_file:
                        self._log_final_verdict(log_file, parsed, iterations, elapsed)
                    
                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "Could not parse response"),
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                    )
                
                # Fetch additional context
                if verbose:
                    print(f"    Fetching additional context: {context_needed}")
                
                additional = context_provider.get_additional_context(
                    repo_name=finding.repo_name,
                    lang=finding.lang,
                    context_requests=context_needed,
                )
                
                if not additional:
                    elapsed = time.time() - start_time
                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "") + " [No additional context available]",
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                    )
                
                # Build follow-up
                follow_up = self.prompt_builder.build_followup_prompt(additional)
                
                if log_file:
                    log_file.write(f"### Follow-up Prompt (Iteration {iterations} -> {iterations+1})\n\n")
                    log_file.write(f"```\n{follow_up}\n```\n\n")
                
                messages.append({"role": "assistant", "content": raw_response})
                messages.append({"role": "user", "content": follow_up})
                
            except Exception as e:
                elapsed = time.time() - start_time
                if verbose:
                    print(f"    ERROR: {e}")
                return Verdict(
                    finding=finding,
                    verdict="Error",
                    confidence="Low",
                    reasoning=f"LLM call failed: {e}",
                    answers=[],
                    raw_response=str(e),
                    model=self.model,
                    elapsed_seconds=elapsed,
                    iterations=iterations,
                )
        
        # Max iterations reached
        elapsed = time.time() - start_time
        return Verdict(
            finding=finding,
            verdict="Needs More Data",
            confidence="Low",
            reasoning=f"Max iterations ({max_iterations}) reached without final verdict",
            answers=[],
            raw_response="\n---\n".join(all_raw_responses),
            model=self.model,
            elapsed_seconds=elapsed,
            iterations=iterations,
        )
    
    def _parse_response(self, raw: str) -> dict[str, Any]:
        """Parse JSON from LLM response."""
        # Try to extract JSON from markdown code block
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # Try direct JSON parse
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON object in response
        brace_match = re.search(r'\{.*\}', raw, re.DOTALL)
        if brace_match:
            try:
                parsed = json.loads(brace_match.group())
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # Manual extraction as fallback
        result: dict[str, Any] = {
            "answers": [],
            "verdict": "Needs More Data",
            "confidence": "Low",
            "reasoning": "",
        }
        
        for v in ["True Positive", "False Positive", "Needs More Data"]:
            if v.lower() in raw.lower():
                result["verdict"] = v
                break
        
        for c in ["High", "Medium", "Low"]:
            if f'confidence": "{c}' in raw or f'confidence":"{c}' in raw:
                result["confidence"] = c
                break
        
        result["reasoning"] = raw[:500]
        return result
    
    def _log_final_verdict(
        self,
        log_file: Any,
        parsed: dict,
        iterations: int,
        elapsed: float,
    ) -> None:
        """Log final verdict to file."""
        log_file.write("### Final Verdict\n\n")
        log_file.write(f"- **Verdict**: {parsed.get('verdict', 'Unknown')}\n")
        log_file.write(f"- **Confidence**: {parsed.get('confidence', 'Low')}\n")
        log_file.write(f"- **Iterations**: {iterations}\n")
        log_file.write(f"- **Time**: {elapsed:.2f}s\n")
        log_file.write(f"- **Reasoning**: {parsed.get('reasoning', 'N/A')}\n\n")
        if parsed.get("answers"):
            log_file.write("**Answers:**\n")
            for ai, ans in enumerate(parsed.get("answers", []), 1):
                log_file.write(f"{ai}. {ans}\n")
            log_file.write("\n")
        log_file.write("---\n\n")
