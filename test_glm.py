import requests
import json

import socket
import urllib3.util.connection as urllib3_conn

# 强制 DNS 解析只返回 IPv4，避免连接阶段优先尝试 IPv6 卡住
urllib3_conn.allowed_gai_family = lambda: socket.AF_INET

TIMEOUT_S = 30

# First API call with reasoning
print("[First call] sending request...")
response = requests.post(
  url="https://openrouter.ai/api/v1/chat/completions",
  headers={
    "Authorization": "Bearer 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",
    "Content-Type": "application/json",
  },
  data=json.dumps({
    "model": "z-ai/glm-5",
    "messages": [
        {
          "role": "user",
          "content": "How many r's are in the word 'strawberry'?"
        }
      ],
    "reasoning": {"enabled": True}
  }),
  timeout=TIMEOUT_S,
)

if response.status_code != 200:
  print("[First call] HTTP", response.status_code)
  print("[First call] Body:", response.text)
  raise SystemExit(1)

raw1 = response.json()
if not raw1.get("choices"):
  print("[First call] Unexpected JSON:", raw1)
  raise SystemExit(1)

# Extract the assistant message with reasoning_details
response = raw1['choices'][0]['message']
print("[First call] assistant.content:", response.get('content'))
print("[First call] assistant.reasoning_details present:", response.get('reasoning_details') is not None)

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.get('content'),
    "reasoning_details": response.get('reasoning_details')  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
print("[Second call] sending request...")
response2 = requests.post(
  url="https://openrouter.ai/api/v1/chat/completions",
  data=json.dumps({
    "model": "z-ai/glm-5",
    "messages": messages,  # Includes preserved reasoning_details
    "reasoning": {"enabled": True}
  }),
  timeout=TIMEOUT_S,
)

if response2.status_code != 200:
  print("[Second call] HTTP", response2.status_code)
  print("[Second call] Body:", response2.text)
  raise SystemExit(1)

raw2 = response2.json()
if not raw2.get("choices"):
  print("[Second call] Unexpected JSON:", raw2)
  raise SystemExit(1)

assistant2 = raw2['choices'][0]['message']
print("[Second call] assistant.content:", assistant2.get('content'))
print("[Second call] assistant.reasoning_details present:", assistant2.get('reasoning_details') is not None)