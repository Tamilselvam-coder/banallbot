import os
from dotenv import load_dotenv

if os.path.exists(".env"):
    load_dotenv(".env")

def make_int(str_input):
    str_list = str_input.split(" ")
    int_list = []
    for x in str_list:
        int_list.append(int(x))
    return int_list

class Var:
    API_ID = int(os.getenv("API_ID", "28046715"))
    API_HASH = os.getenv("API_HASH", " 203a6455ceb4497e2b6347a14bc45df4 ")
    BOT_TOKEN = os.getenv("BOT_TOKEN", "7729055600:AAE2e7otuYborAmOudi4obTCPpXceW6OsbU")
    sudo = os.getenv("SUDO")
    SUDO = [1231933846]
    if sudo:
        SUDO = make_int(sudo)
