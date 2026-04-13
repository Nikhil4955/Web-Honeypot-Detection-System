import os
import json
import re
from emergentintegrations.llm.chat import LlmChat, UserMessage

SYSTEM_PROMPT = """You are SOIN AI, an expert software engineer assistant. When a user asks you to create files or code, respond ONLY with valid JSON in this exact format — no text before or after:

{"fileTree":{"filename.js":"file content here","package.json":"{\\"name\\":\\"app\\"}"},"buildCommand":"npm install","startCommand":"node filename.js"}

Rules:
1. Return ONLY the JSON object — no markdown, no explanations, no prefix text
2. fileTree keys are file paths, values are complete file contents as strings
3. For general questions not about creating files, respond normally in plain text
"""

async def get_ai_response(message: str, session_id: str) -> str:
    try:
        api_key = os.environ.get("EMERGENT_LLM_KEY")
        if not api_key:
            return "Error: AI service not configured"
        
        chat = LlmChat(
            api_key=api_key,
            session_id=f"soin_{session_id}",
            system_message=SYSTEM_PROMPT
        )
        chat.with_model("gemini", "gemini-3-flash-preview")
        
        user_message = UserMessage(text=message)
        response = await chat.send_message(user_message)
        
        return response
    except Exception as e:
        return f"Error: {str(e)}"

def parse_ai_response(response: str) -> dict:
    """Robustly extract JSON from AI response, handling prefixes, code blocks, etc."""
    if not response or not isinstance(response, str):
        return {"message": str(response)}
    
    text = response.strip()
    
    # 1. Try direct JSON parse
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, TypeError):
        pass
    
    # 2. Extract from ```json ... ``` blocks
    json_block = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', text)
    if json_block:
        try:
            result = json.loads(json_block.group(1).strip())
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass
    
    # 3. Find the first { ... } block (greedy match for outermost braces)
    brace_start = text.find('{')
    if brace_start != -1:
        # Find matching closing brace
        depth = 0
        brace_end = -1
        for i in range(brace_start, len(text)):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    brace_end = i
                    break
        
        if brace_end > brace_start:
            json_str = text[brace_start:brace_end + 1]
            try:
                result = json.loads(json_str)
                if isinstance(result, dict):
                    return result
            except (json.JSONDecodeError, TypeError):
                pass
    
    # 4. Not JSON — return as plain message
    return {"message": text}
