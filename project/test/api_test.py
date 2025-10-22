from core.api_handler import OpenAIClient

openai = OpenAIClient()

list = openai.test_connection()

result = openai.send_prompt("This is a test message and will work inshallah")

print(result)
print(list)