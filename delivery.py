import os
import requests
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")


def send_message(text):
    if not WEBHOOK_URL:
        raise SystemExit("DISCORD_WEBHOOK_URL is not set. Check your .env file.")

    payload = {
        "content": text,
        "allowed_mentions": {"parse": []},
    }
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
    except requests.RequestException as error:
        raise SystemExit(f"Could not reach Discord ({type(error).__name__}).") from None

    print("Discord answered with status:", response.status_code)
    if not response.ok:
        raise SystemExit(f"Discord rejected the message with status {response.status_code}.")


if __name__ == "__main__":
    send_message("Hello from secdigest. Layer 0 works.")