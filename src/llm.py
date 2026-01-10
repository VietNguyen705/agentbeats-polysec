"""Multi-LLM provider interface for CyberGym Green Agent."""

import os
import json
from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLM(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        schema: type[T] | None = None,
    ) -> str | T:
        """Generate completion. Returns parsed model if schema provided."""
        pass


class OpenAILLM(LLM):
    """OpenAI GPT-4o provider."""

    def __init__(self, model: str = "gpt-4o"):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs = {"model": self.model, "messages": messages}
        if schema:
            kwargs["response_format"] = {"type": "json_object"}
            # Build clear field descriptions
            fields = schema.model_fields
            field_desc = ", ".join([f'"{k}": <{v.annotation.__name__ if hasattr(v.annotation, "__name__") else "value"}>' for k, v in fields.items()])
            messages[-1]["content"] += f"\n\nYou MUST respond with a JSON object containing these fields with actual values (not schema definitions): {{{field_desc}}}"

        response = await self.client.chat.completions.create(**kwargs)
        text = response.choices[0].message.content

        if schema:
            return schema.model_validate_json(text)
        return text


class ClaudeLLM(LLM):
    """Anthropic Claude provider."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        from anthropic import AsyncAnthropic
        self.client = AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        kwargs = {"model": self.model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]}
        if system:
            kwargs["system"] = system

        if schema:
            # Use tool use for structured output
            kwargs["tools"] = [{
                "name": "respond",
                "description": "Respond with structured data",
                "input_schema": schema.model_json_schema(),
            }]
            kwargs["tool_choice"] = {"type": "tool", "name": "respond"}

        response = await self.client.messages.create(**kwargs)

        if schema:
            for block in response.content:
                if block.type == "tool_use":
                    return schema.model_validate(block.input)
            raise ValueError("No tool use in response")

        return response.content[0].text


class GeminiLLM(LLM):
    """Google Gemini provider."""

    def __init__(self, model: str = "gemini-2.5-flash"):
        from google import genai
        self.client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        from google.genai import types

        config = types.GenerateContentConfig()
        if system:
            config.system_instruction = system
        if schema:
            config.response_mime_type = "application/json"
            config.response_schema = schema

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=config,
        )

        if schema:
            return response.parsed
        return response.text


class NovaLLM(LLM):
    """AWS Bedrock Nova provider."""

    def __init__(self, model: str = "amazon.nova-pro-v1:0"):
        import boto3
        self.client = boto3.client(
            "bedrock-runtime",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
        )
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        messages = [{"role": "user", "content": [{"text": prompt}]}]

        if schema:
            fields = schema.model_fields
            field_desc = ", ".join([f'"{k}": <{v.annotation.__name__ if hasattr(v.annotation, "__name__") else "value"}>' for k, v in fields.items()])
            messages[0]["content"][0]["text"] += f"\n\nYou MUST respond with a JSON object containing these fields with actual values: {{{field_desc}}}"

        kwargs = {"modelId": self.model, "messages": messages}
        if system:
            kwargs["system"] = [{"text": system}]

        response = self.client.converse(**kwargs)
        text = response["output"]["message"]["content"][0]["text"]

        if schema:
            return schema.model_validate_json(text)
        return text


class GrokLLM(LLM):
    """xAI Grok provider (OpenAI-compatible)."""

    def __init__(self, model: str = "grok-2"):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(
            api_key=os.getenv("XAI_API_KEY"),
            base_url="https://api.x.ai/v1",
        )
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs = {"model": self.model, "messages": messages}
        if schema:
            kwargs["response_format"] = {"type": "json_object"}
            fields = schema.model_fields
            field_desc = ", ".join([f'"{k}": <{v.annotation.__name__ if hasattr(v.annotation, "__name__") else "value"}>' for k, v in fields.items()])
            messages[-1]["content"] += f"\n\nYou MUST respond with a JSON object containing these fields with actual values: {{{field_desc}}}"

        response = await self.client.chat.completions.create(**kwargs)
        text = response.choices[0].message.content

        if schema:
            return schema.model_validate_json(text)
        return text


class DeepSeekLLM(LLM):
    """DeepSeek provider (OpenAI-compatible)."""

    def __init__(self, model: str = "deepseek-chat"):
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com/v1",
        )
        self.model = model

    async def complete(self, prompt: str, system: str | None = None, schema: type[T] | None = None) -> str | T:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        kwargs = {"model": self.model, "messages": messages}
        if schema:
            kwargs["response_format"] = {"type": "json_object"}
            fields = schema.model_fields
            field_desc = ", ".join([f'"{k}": <{v.annotation.__name__ if hasattr(v.annotation, "__name__") else "value"}>' for k, v in fields.items()])
            messages[-1]["content"] += f"\n\nYou MUST respond with a JSON object containing these fields with actual values: {{{field_desc}}}"

        response = await self.client.chat.completions.create(**kwargs)
        text = response.choices[0].message.content

        if schema:
            return schema.model_validate_json(text)
        return text


# Provider registry
PROVIDERS: dict[str, type[LLM]] = {
    "openai": OpenAILLM,
    "claude": ClaudeLLM,
    "gemini": GeminiLLM,
    "nova": NovaLLM,
    "grok": GrokLLM,
    "deepseek": DeepSeekLLM,
}


def get_llm(provider: str = "openai") -> LLM:
    """Get LLM instance by provider name."""
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}. Available: {list(PROVIDERS.keys())}")
    return PROVIDERS[provider]()
