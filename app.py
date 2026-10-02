import os
from dotenv import load_dotenv
from openai import OpenAI

# 1. Загружаем переменные из .env
load_dotenv()

# 2. Создаём клиент для OpenRouter
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

# 3. Читаем лог-файл
with open("auth.log", "r", encoding="utf-8") as f:
    log_content = f.read()

# 4. Формируем промпт
prompt = f"""Ты — эксперт по кибербезопасности.
Проанализируй следующие строки лога SSH и определи, есть ли среди них признаки атаки.
Если да — опиши, что происходит, и какие IP-адреса подозрительны.
Если нет — кратко напиши, что всё чисто.

Лог:
{log_content}
"""

# 5. Отправляем запрос в нейросеть
response = client.chat.completions.create(
    model="qwen/qwen3.8-27b:free",
    messages=[
        {"role": "user", "content": prompt}
    ],
)

# 6. Печатаем ответ
print(response.choices[0].message.content)