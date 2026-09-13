import os
from openai import OpenAI
from groq import Groq
from dotenv import load_dotenv
import anthropic
load_dotenv(override=True)


class ApiHandlerRouter:
    def __init__(self):
        self.handlers = {
            "openai": OpenAIClient(),
            "groq": GroqClient(),
            "claude": ClaudeClient(), 
        }
    def send_prompt(self, in_prompt: str, producer: str) -> str:
        "Route to true client according to input"
        handler = self.handlers.get(producer.lower())
        if handler is None:
            raise ValueError(f"Unsupported producer: {producer}")
        return handler.send_prompt(in_prompt=in_prompt)

    def get_model(self, producer: str) -> str:
        """The exact model string a producer is currently configured with --
        for recording alongside generated samples (`producer` alone is just
        "openai"/"groq"/"claude" and doesn't survive a provider swapping
        which model backs it, e.g. Groq retiring llama-3.3-70b-versatile
        2026-09-09 in favor of qwen/qwen3.8-27b -- see changes_summary.md).
        """
        handler = self.handlers.get(producer.lower())
        if handler is None:
            raise ValueError(f"Unsupported producer: {producer}")
        return handler.model_in

class OpenAIClient:
    def __init__(self, model_in="gpt-4.1-2025-04-14"):
        self.api_key = os.getenv("openai_key")
        if not self.api_key:
            raise ValueError("OpenAI API key is not found")
        self.client = OpenAI(api_key=self.api_key)
        self.model_in = model_in

    def send_prompt(self, in_prompt: str, model_temp=None, temperature=1.0,
                     system="You write or check Python - Flask codes for CWE database",
                     response_format=None):
        kwargs = {}
        if response_format is not None:
            kwargs["response_format"] = response_format
        response = self.client.chat.completions.create(
            model=model_temp or self.model_in,
            messages=[{"role": "system", "content": system},
              {"role": "user", "content": in_prompt}],
            temperature=temperature,
            **kwargs,
        )
        return response.choices[0].message.content.strip()
    
    def test_connection(self):
        try:
            return [model.id for model in self.client.models.list().data]
        except Exception as e:
            print(f"[!] Openai connection failed: {e}")
            return None
        
        
class GroqClient:
    # llama-3.3-70b-versatile was retired from Groq's platform (2026-09-09,
    # confirmed via client.models.list() -- no Llama chat model remains
    # available at all, only groq/compound, qwen/qwen*, openai/gpt-oss-*,
    # allam-2-7b, plus audio/prompt-guard models). Swapped to qwen/qwen3.8-27b
    # per user decision -- see changes_summary.md's 2026-09-09 entry. Samples
    # generated before this change keep producer="groq" with no recorded
    # model (pre-dates the producer_model column); samples from now on
    # record the exact model via ApiHandlerRouter.get_model() /
    # DBManager.fill_row_to_database()'s producer_model column.
    def __init__(self, model_in = "qwen/qwen3.8-27b"):
        self.api_key = os.getenv("groq_key")
        if not self.api_key:
            raise ValueError("Groq API key is not found")
        self.client = Groq(api_key=self.api_key)
        self.model_in = model_in

    def send_prompt(self, in_prompt: str, temperature=1.0,
                     system="You write or check Python - Flask codes for CWE database"):
        response = self.client.chat.completions.create(
        model=self.model_in,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": in_prompt}
            ],
            temperature=temperature,
        )
        return response.choices[0].message.content.strip()
    def test_connection(self):
        try:
            return [model.id for model in self.client.models.list().data]
        except Exception as e:
            print(f"[!] Groq connection failed: {e}")
            return None

class ClaudeClient:
    def __init__(self, model_in="claude-haiku-4-5"):   # claude-sonnet-4-5 idi sonradan haiku yaptım 
        self.api_key = os.getenv("claude_key")          # .env'e CLAUDE_KEY ekle
        if not self.api_key:
            raise ValueError("Claude API key is not found")
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model_in = model_in

    def send_prompt(self, in_prompt: str, temperature=None,
                     system="You write or check Python - Flask codes for CWE database"):
        kwargs = {}
        if temperature is not None:
            kwargs["temperature"] = temperature
        response = self.client.messages.create(
            model=self.model_in,
            max_tokens=8096,
            system=system,
            messages=[{"role": "user", "content": in_prompt}],
            **kwargs,
        )
        return response.content[0].text.strip()

    def test_connection(self):
        try:
            # Minimal bir istek atarak bağlantıyı test et
            self.client.messages.create(
                model=self.model_in,
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception as e:
            print(f"[!] Claude connection failed: {e}")
            return None