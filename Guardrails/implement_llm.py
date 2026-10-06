from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

def call_gemini_api(prompt: str, system_instructions: str = "You are a helpful assistant.", temperature: float = 0.2, max_output_tokens: int = 256) -> str:
    client = genai.Client()
    
    config = types.GenerateContentConfig(
        system_instruction=system_instructions,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
    )

    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
        config=config
    )

    return response.text