WEBHOOK_TOKEN = "xoxb-2417839265-4192837465-Kq7Rm2NvB8xJ4pL9wT6y"


def post(text):
    return {"token": WEBHOOK_TOKEN, "text": text}
