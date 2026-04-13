import os
import json
from emergentintegrations.llm.chat import LlmChat, UserMessage

SYSTEM_PROMPT = """You are SOIN AI, an expert software engineer assistant. When a user asks you to create files or code, you MUST respond ONLY with valid JSON in this exact format:

{
  "fileTree": {
    "filename1.js": "file content here",
    "filename2.json": "file content here",
    "folder/file.css": "file content here"
  },
  "buildCommand": "npm install",
  "startCommand": "npm start"
}

Rules:
1. ONLY return JSON, no markdown code blocks, no explanations before or after
2. fileTree keys are file paths (use / for folders)
3. fileTree values are the complete file contents as strings
4. buildCommand is the command to install dependencies
5. startCommand is the command to run the project
6. For general questions not about creating files, respond normally but keep it concise

Example valid response:
{"fileTree":{"app.js":"console.log('hello');","package.json":"{\\"name\\":\\"test\\"}"}, "buildCommand":"npm install", "startCommand":"node app.js"}
"""

async def get_ai_response(message: str, session_id: str) -> str:
    try:
        api_key = os.environ.get("EMERGENT_LLM_KEY")
        if not api_key:
            return "Error: AI service not configured"
        
        chat = LlmChat(
            api_key=api_key,
            session_id=session_id,
            system_message=SYSTEM_PROMPT
        )
        chat.with_model("gemini", "gemini-3-flash-preview")
        
        user_message = UserMessage(text=message)
        response = await chat.send_message(user_message)
        
        return response
    except Exception as e:
        return f"Error: {str(e)}"

def parse_ai_response(response: str) -> dict:
    """Try to extract JSON from AI response"""
    try:
        # Try direct JSON parse
        return json.loads(response)
    except:
        # Try to extract JSON from markdown code blocks
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            json_str = response[start:end].strip()
            return json.loads(json_str)
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            json_str = response[start:end].strip()
            return json.loads(json_str)
        else:
            # Response is not JSON, return as plain message
            return {"message": response}
