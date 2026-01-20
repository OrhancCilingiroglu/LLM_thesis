import os
from openai import OpenAI
from groq import Groq
from dotenv import load_dotenv
load_dotenv(override=True)


class ApiHandlerRouter:
    def __init__(self):
        self.handlers = {
            "openai": OpenAIClient(),
            "groq": GroqClient(),
        }
    def send_prompt(self, in_prompt: str, producer: str) -> str:
        "Route to true client according to input"
        handler = self.handlers.get(producer.lower())
        if handler is None:
            raise ValueError(f"Unsupported producer: {producer}")
        return handler.send_prompt(in_prompt=in_prompt)

class OpenAIClient:
    def __init__(self):
        self.api_key = os.getenv("openai_key")
        if not self.api_key:
            raise ValueError("OpenAI API key is not found")
        self.client = OpenAI(api_key=self.api_key)

    def send_prompt(self, in_prompt: str, model_temp="gpt-4.1-2025-04-14"):
        response = self.client.chat.completions.create(
            model=model_temp,
            messages=[{"role": "system", "content": "You write or check Python - Flask codes for CWE database"},
              {"role": "user", "content": in_prompt}],
            temperature = 1.0
        )
        return response.choices[0].message.content.strip()
    
    def test_connection(self):
        try:
            return [model.id for model in self.client.models.list().data]
        except Exception as e:
            print(f"[!] Openai connection failed: {e}")
            return None
        
        
class GroqClient:
    def __init__(self, model_in = "llama-3.3-70b-versatile"):
        self.api_key = os.getenv("groq_key")
        if not self.api_key:
            raise ValueError("Groq API key is not found")
        self.client = Groq(api_key=self.api_key)
        self.model_in = model_in

    def send_prompt(self, in_prompt: str):
        response = self.client.chat.completions.create(
        model=self.model_in,
        messages=[
            {"role": "system", "content": "You write or check Python - Flask codes for CWE database"},
            {"role": "user", "content": in_prompt}
            ],
            temperature=1.0,
        )
        return response.choices[0].message.content.strip()
    def test_connection(self):
        try:
            return [model.id for model in self.client.models.list().data]
        except Exception as e:
            print(f"[!] Groq connection failed: {e}")
            return None
