import logging
import re
import os
import sys
import asyncio
import pickle # For potentially saving login state across restarts (optional, complex)
from telethon import TelegramClient, events, functions, types, errors, sessions
from telethon.tl.types import (
    ChannelParticipantsAdmins, ChannelParticipantsKicked, ChatBannedRights, User
)
from telethon.tl.functions.channels import (
    LeaveChannelRequest, EditBannedRequest, GetParticipantRequest
)
from telethon.errors.rpcerrorlist import (
    FloodWaitError, UserAdminInvalidError, ChatAdminRequiredError,
    UserNotParticipantError, ChatWriteForbiddenError, UserCreatorError,
    UserIdInvalidError, PeerIdInvalidError, UsernameNotOccupiedError,
    SessionPasswordNeededError, PhoneCodeInvalidError, ApiIdInvalidError,
    PhoneNumberInvalidError, ApiIdPublishedFloodError
)
from telethon.utils import get_peer_id, get_display_name
from datetime import datetime
from time import sleep
from var import Var # Bot's API_ID, API_HASH, BOT_TOKEN, SUDO list

# --- Constants ---
SUDO_FILE = "sudo_users.txt"
USER_SESSIONS_DIR = "user_sessions/" # Directory to store user session files
ACTION_SLEEP_INTERVAL = 0.8 # Base sleep time

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Suppress noisy Telethon connection logs if desired
# logging.getLogger('telethon').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# --- Global Variables ---
# Dictionary to hold active client sessions for logged-in users {user_id: TelegramClient}
user_clients = {}
# Dictionary to track login process state {user_id: {'stage': 'api_id', 'data': {}}}
login_sessions = {}

# --- Dynamic SUDO Users List ---
CORE_SUDO_USERS = set()
try:
    for user_id in Var.SUDO:
        CORE_SUDO_USERS.add(int(user_id))
    logger.info(f"Core SUDO users loaded from Var: {CORE_SUDO_USERS}")
except AttributeError:
    logger.warning("Var.SUDO not found or invalid in var.py.")
except ValueError:
    logger.warning("Var.SUDO contains non-integer values.")

DYNAMIC_SUDO_USERS = set()
try:
    with open(SUDO_FILE, 'r') as f:
        for line in f:
            try: DYNAMIC_SUDO_USERS.add(int(line.strip()))
            except ValueError: logger.warning(f"Skipping invalid line in {SUDO_FILE}: {line.strip()}")
    logger.info(f"Dynamic SUDO users loaded from {SUDO_FILE}: {DYNAMIC_SUDO_USERS}")
except FileNotFoundError:
    logger.info(f"{SUDO_FILE} not found.")
except Exception as e:
    logger.error(f"Error reading {SUDO_FILE}: {e}")

SUDO_USERS = CORE_SUDO_USERS.union(DYNAMIC_SUDO_USERS)
logger.info(f"Total active SUDO users: {SUDO_USERS}")

# --- Initialize Bot's Main Telegram Client ---
try:
    # Ensure user sessions directory exists
    os.makedirs(USER_SESSIONS_DIR, exist_ok=True)

    # Use a distinct session name for the bot itself
    bot_session_name = "DaxxBotSession"
    client = TelegramClient(
        sessions.StringSession(), # Use StringSession to avoid file conflict if run as user
        Var.API_ID,
        Var.API_HASH
    )
    # Load bot session string from Var if available (for persistence without file)
    if hasattr(Var, 'BOT_SESSION_STRING') and Var.BOT_SESSION_STRING:
         client.session = sessions.StringSession(Var.BOT_SESSION_STRING)
         logger.info("Loaded bot session from Var.BOT_SESSION_STRING.")
    else:
         # Fallback to file session if no string session in Var
         logger.info("No BOT_SESSION_STRING in Var, using file session for bot.")
         client.session = sessions.Session(bot_session_name)

except Exception as e:
    logger.critical(f"Failed to initialize Bot's Telegram Client: {e}")
    sys.exit(1)

# --- Helper Functions ---

async def get_target_chat_id(event, client_to_use):
    """Gets the target chat ID or username from the command arguments."""
    parts = event.text.split(maxsplit=2)
    if len(parts) < 2:
        await event.reply("Please specify the target Chat ID or Username after the command.")
        return None
    target_identifier = parts[1]
    try:
        # Try converting to int (chat ID)
        target_chat = await client_to_use.get_entity(int(target_identifier))
        return target_chat.id
    except ValueError:
        # Try as username or group link
        try:
            target_chat = await client_to_use.get_entity(target_identifier)
            return target_chat.id
        except (ValueError, PeerIdInvalidError, UsernameNotOccupiedError, TypeError) as e:
            await event.reply(f"Could not find chat: `{target_identifier}`. Error: {type(e).__name__}")
            return None
        except Exception as e:
            await event.reply(f"An error occurred while resolving `{target_identifier}`: {e}")
            return None
    except Exception as e:
        await event.reply(f"An error occurred: {e}")
        return None

async def check_client_permissions(event, client_to_use, target_chat_id, rights_needed):
    """Checks if the specified client has the necessary admin rights in the target chat."""
    if not target_chat_id: return False # Cannot check without target
    try:
        chat = await client_to_use.get_entity(target_chat_id)
        me = await client_to_use.get_me()

        if isinstance(chat, types.User):
             # Permissions don't apply directly to users in this context
             return True # Or False depending on command logic

        permissions = await client_to_use.get_permissions(chat, me)

        # Handle cases where permissions might be None (e.g., not in chat)
        if not permissions:
             # Check if it's a public channel the client might be able to write to without being admin
             # This check is basic; real permission depends on the action
             if hasattr(chat, 'username') and chat.username:
                 logger.warning(f"Client {me.id} might not be in chat {target_chat_id}, assuming public access possible.")
                 # Let the action attempt proceed, it will fail if rights are truly missing
                 return True
             else:
                 await event.reply(f"Client `{me.id}` doesn't seem to be in chat `{target_chat_id}` or cannot get permissions.")
                 return False


        if not permissions.is_admin and 'admin' in rights_needed: # Check if admin status itself is needed
             await event.reply(f"Client `{me.id}` is not an admin in chat `{target_chat_id}`.")
             return False

        missing_rights = []
        if 'ban' in rights_needed and not permissions.ban_users:
            missing_rights.append("ban users")
        if 'kick' in rights_needed and not permissions.kick_users:
            missing_rights.append("kick users")
        # Add other permission checks as needed

        if missing_rights:
            await event.reply(f"Client `{me.id}` lacks permission(s) in chat `{target_chat_id}`: {', '.join(missing_rights)}.")
            return False

        return True # Has necessary rights

    except UserNotParticipantError:
         await event.reply(f"Client `{me.id}` is not a participant in chat `{target_chat_id}`.")
         return False
    except (ChatAdminRequiredError, errors.ChannelPrivateError, errors.ChatForbiddenError):
        await event.reply(f"Client `{me.id}` lacks admin rights or access to chat `{target_chat_id}` permissions.")
        return False
    except Exception as e:
        logger.error(f"Error checking permissions for client {me.id if 'me' in locals() else 'N/A'} in chat {target_chat_id}: {e}")
        await event.reply(f"An error occurred while checking permissions: {e}")
        return False

async def get_user_id_from_event(event):
    """Gets user ID from command argument or reply. (From previous code)"""
    user_id = None
    target_user = None
    if event.reply_to_msg_id:
        reply_message = await event.get_reply_message()
        if reply_message and reply_message.from_id:
            user_peer = reply_message.from_id
            user_id = get_peer_id(user_peer)
            try: target_user = await client.get_entity(user_peer)
            except Exception: pass
            logger.info(f"Target user identified from reply: {user_id}")
    if not user_id:
        parts = event.text.split(maxsplit=2)
        if len(parts) > 1:
            identifier = parts[1]
            try:
                user_id = int(identifier)
                logger.info(f"Target user identified from argument (ID): {user_id}")
                try: target_user = await client.get_entity(user_id)
                except Exception: pass
            except ValueError:
                logger.info(f"Target user identified from argument (Username): {identifier}")
                try:
                    target_user = await client.get_entity(identifier)
                    user_id = target_user.id
                except (UsernameNotOccupiedError, ValueError, TypeError):
                    await event.reply(f"Could not find user: {identifier}")
                    return None, None
                except Exception as e:
                    await event.reply(f"Error fetching user {identifier}: {type(e).__name__}")
                    return None, None
    if isinstance(user_id, int): return user_id, target_user
    else:
        if len(event.text.split()) == 1 and not event.reply_to_msg_id:
             await event.reply("Reply to a user or provide their User ID or Username.")
        elif not user_id: await event.reply("Could not identify the target user.")
        return None, None

# --- Login/Logout Handlers ---

@client.on(events.NewMessage(pattern="^/login$", func=lambda e: e.is_private and e.sender_id in SUDO_USERS))
async def login_start(event):
    """Starts the login process for a SUDO user."""
    user_id = event.sender_id
    if user_id in user_clients:
        await event.reply("You are already logged in. Use /logout first if you want to switch accounts.")
        return
    if user_id in login_sessions:
        await event.reply("You are already in the middle of a login process. Please complete or cancel it.")
        return

    login_sessions[user_id] = {'stage': 'api_id', 'data': {}}
    logger.info(f"Login process started for user {user_id}")
    await event.reply("Starting login process...\n\nPlease send your **API ID**.")

@client.on(events.NewMessage(func=lambda e: e.is_private and e.sender_id in login_sessions))
async def login_handler(event):
    """Handles interactive login steps."""
    user_id = event.sender_id
    session_state = login_sessions.get(user_id)
    if not session_state: return # Should not happen if filter works

    stage = session_state['stage']
    data = session_state['data']
    message_text = event.text.strip()

    try:
        if stage == 'api_id':
            try:
                data['api_id'] = int(message_text)
                session_state['stage'] = 'api_hash'
                await event.reply("API ID received. Now please send your **API Hash**.")
            except ValueError:
                await event.reply("Invalid API ID. Please send a number.")
                return

        elif stage == 'api_hash':
            data['api_hash'] = message_text
            session_state['stage'] = 'phone'
            await event.reply("API Hash received. Now please send your **Phone Number** (with country code, e.g., +1234567890).")

        elif stage == 'phone':
            data['phone'] = message_text
            session_state['stage'] = 'connecting' # Mark as connecting to prevent race conditions
            await event.reply("Credentials received. Attempting to connect...")

            # --- Attempt Connection ---
            user_session_file = os.path.join(USER_SESSIONS_DIR, f"user_{user_id}.session")
            temp_client = TelegramClient(
                sessions.Session(user_session_file),
                data['api_id'],
                data['api_hash'],
                # Set device model and system version for better session handling
                device_model="DaxxManagerBot",
                system_version="1.0"
            )

            try:
                logger.info(f"Attempting to connect client for user {user_id} with phone {data['phone']}")
                await temp_client.connect()

                if not await temp_client.is_user_authorized():
                    logger.info(f"User {user_id} is not authorized. Requesting code.")
                    phone_code_hash = (await temp_client.send_code_request(data['phone'])).phone_code_hash
                    data['phone_code_hash'] = phone_code_hash
                    session_state['stage'] = 'code'
                    # Store client temporarily for code/password entry
                    login_sessions[user_id]['client'] = temp_client
                    await event.reply("Connection successful. Please send the login **Code** you received via Telegram.")
                else:
                    logger.info(f"User {user_id} is already authorized.")
                    user_clients[user_id] = temp_client
                    del login_sessions[user_id] # Clean up login state
                    me = await temp_client.get_me()
                    await event.reply(f"✅ Successfully logged in as {get_display_name(me)} (`{me.id}`).")

            except (ApiIdInvalidError, ApiIdPublishedFloodError):
                await event.reply("❌ Login failed: Invalid API ID or API Hash.")
                del login_sessions[user_id]
            except PhoneNumberInvalidError:
                await event.reply("❌ Login failed: Invalid Phone Number format. Use format like +1234567890.")
                del login_sessions[user_id]
            except FloodWaitError as fwe:
                 await event.reply(f"❌ Login failed: Flood wait. Try again in {fwe.seconds} seconds.")
                 del login_sessions[user_id]
            except Exception as e:
                logger.error(f"Error during user {user_id} connection attempt: {e}")
                await event.reply(f"❌ An unexpected error occurred during connection: {type(e).__name__}")
                if 'temp_client' in locals() and temp_client.is_connected():
                    await temp_client.disconnect()
                del login_sessions[user_id]


        elif stage == 'code':
            code = message_text
            temp_client = session_state.get('client')
            if not temp_client:
                await event.reply("Error: Lost connection state. Please start /login again.")
                del login_sessions[user_id]
                return

            try:
                await temp_client.sign_in(data['phone'], code, phone_code_hash=data['phone_code_hash'])
                logger.info(f"User {user_id} signed in successfully with code.")
                user_clients[user_id] = temp_client # Store the successful client
                del login_sessions[user_id] # Clean up
                me = await temp_client.get_me()
                await event.reply(f"✅ Successfully logged in as {get_display_name(me)} (`{me.id}`).")

            except PhoneCodeInvalidError:
                await event.reply("❌ Invalid code. Please try sending the code again.")
                # Stay in 'code' stage
            except SessionPasswordNeededError:
                logger.info(f"User {user_id} needs 2FA password.")
                session_state['stage'] = 'password'
                await event.reply("Two-factor authentication enabled. Please send your **Password**.")
            except FloodWaitError as fwe:
                 await event.reply(f"❌ Login failed: Flood wait. Try again in {fwe.seconds} seconds.")
                 await temp_client.disconnect()
                 del login_sessions[user_id]
            except Exception as e:
                logger.error(f"Error during user {user_id} sign in: {e}")
                await event.reply(f"❌ An error occurred during sign in: {type(e).__name__}")
                await temp_client.disconnect()
                del login_sessions[user_id]

        elif stage == 'password':
            password = message_text
            temp_client = session_state.get('client')
            if not temp_client:
                 await event.reply("Error: Lost connection state. Please start /login again.")
                 del login_sessions[user_id]
                 return

            try:
                await temp_client.sign_in(password=password)
                logger.info(f"User {user_id} signed in successfully with password.")
                user_clients[user_id] = temp_client
                del login_sessions[user_id]
                me = await temp_client.get_me()
                await event.reply(f"✅ Successfully logged in as {get_display_name(me)} (`{me.id}`).")

            except errors.PasswordHashInvalidError:
                await event.reply("❌ Invalid password. Please try sending the password again.")
                # Stay in 'password' stage
            except FloodWaitError as fwe:
                 await event.reply(f"❌ Login failed: Flood wait. Try again in {fwe.seconds} seconds.")
                 await temp_client.disconnect()
                 del login_sessions[user_id]
            except Exception as e:
                logger.error(f"Error during user {user_id} password sign in: {e}")
                await event.reply(f"❌ An error occurred during password sign in: {type(e).__name__}")
                await temp_client.disconnect()
                del login_sessions[user_id]

    except Exception as e:
        # Catchall for unexpected issues during the process
        logger.exception(f"Critical error in login handler for user {user_id}")
        await event.reply("An unexpected error occurred. Login process aborted.")
        if user_id in login_sessions:
            temp_client = login_sessions[user_id].get('client')
            if temp_client and temp_client.is_connected():
                await temp_client.disconnect()
            del login_sessions[user_id]

@client.on(events.NewMessage(pattern="^/logout$", func=lambda e: e.sender_id in SUDO_USERS))
async def logout(event):
    """Logs out the user's managed client session."""
    user_id = event.sender_id
    if user_id in login_sessions:
        # Cancel ongoing login process
        temp_client = login_sessions[user_id].get('client')
        if temp_client and temp_client.is_connected():
            await temp_client.disconnect()
        del login_sessions[user_id]
        await event.reply("Ongoing login process cancelled.")
        return

    user_client = user_clients.get(user_id)
    if not user_client:
        await event.reply("You are not currently logged in.")
        return

    try:
        if user_client.is_connected():
            me = await user_client.get_me()
            await user_client.log_out()
            logger.info(f"User {user_id} ({get_display_name(me)}) logged out.")
            await event.reply(f"✅ Successfully logged out session for {get_display_name(me)} (`{user_id}`).")
        else:
             await event.reply("Your session was already disconnected.")

        # Optionally delete session file - uncomment if desired
        # user_session_file = os.path.join(USER_SESSIONS_DIR, f"user_{user_id}.session")
        # if os.path.exists(user_session_file):
        #     os.remove(user_session_file)
        #     logger.info(f"Removed session file for user {user_id}")

    except Exception as e:
        logger.error(f"Error during logout for user {user_id}: {e}")
        await event.reply(f"An error occurred during logout: {e}")
    finally:
        # Always remove from active clients dict
        if user_id in user_clients:
            del user_clients[user_id]

# --- Standard Bot Commands ---

@client.on(events.NewMessage(pattern="^/start$", func=lambda e: e.is_private))
async def start(event):
    user = await event.get_sender()
    name = get_display_name(user)
    user_id = user.id
    logger.info(f"/start command received from {name} (ID: {user_id})")
    is_sudo = user_id in SUDO_USERS
    welcome_text = (
        f"Hello {name}!\n\n"
        "I am the group and channel ban and unban bot Manager Bot.\n"
    )
    if is_sudo:
        welcome_text += ("You are a SUDO user. You can manage your own Telegram sessions "
                         "using /login and execute commands like `/ubanall` in channels "
                         "where *you* have admin rights, without needing me there.\n"
                         "**Warning:** Logging in shares your session control with this bot instance.\n\n")
    else:
         welcome_text += "I provide certain management functions.\n\n"

    welcome_text += "Type /help to see available commands."
    await event.reply(welcome_text)


@client.on(events.NewMessage(pattern="^/help$"))
async def help_command(event):
    user_id = event.sender_id
    name = get_display_name(await event.get_sender())
    logger.info(f"/help command received from {name} (ID: {user_id})")

    help_text = f"Hi {name}! Commands available:\n\n"
    help_text += "`!ping` - Check bot's responsiveness.\n" # Use !ping for bot ping to avoid conflict if user is logged in
    help_text += "`!start` - Show welcome message (PM only).\n"
    help_text += "`!help` - Show this message.\n"

    if user_id in SUDO_USERS:
        help_text += "\n**SUDO User Management:**\n"
        help_text += "`!addsudo <user_id/reply>` - Add user to bot's SUDO list.\n"
        help_text += "`!delsudo <user_id/reply>` - Remove user from bot's SUDO list.\n"
        help_text += "`!restart` - Restart the bot.\n"

        help_text += "\n**Your Account Management (SUDO Only):**\n"
        help_text += "`!login` - Log in with your own Telegram account.\n"
        help_text += "`!logout` - Log out your account session.\n"

        help_text += "\n**Bot Actions (Requires Bot Admin in Target Chat):**\n"
        help_text += "`!bbanall <chat_id>` - Bot bans all non-admins.\n"
        help_text += "`!bkickall <chat_id>` - Bot kicks all non-admins.\n"
        help_text += "`!bunbanall <chat_id>` - Bot unbans all.\n"
        help_text += "`!bleave [chat_id]` - Bot leaves current or specified chat.\n"

        help_text += "\n**User Actions (Uses Your Logged-in Account, Requires *You* Have Admin in Target Chat):**\n"
        help_text += "`!ubanall <chat_id>` - You ban all non-admins.\n"
        help_text += "`!ukickall <chat_id>` - You kick all non-admins.\n"
        help_text += "`!uunbanall <chat_id>` - You unban all.\n"
        help_text += "`!uleave <chat_id>` - Your account leaves the specified chat.\n"
        help_text += "\n`<chat_id>` can be the numerical ID or the @username / t.me/joinchat link."

    await event.reply(help_text.replace('!', Var.CMD_PREFIX if hasattr(Var, 'CMD_PREFIX') else '/'), parse_mode='md')


@client.on(events.NewMessage(pattern="^/ping$")) # Changed prefix later if needed
async def ping(event):
    # Allow anyone to ping the bot itself
    start = datetime.now()
    reply_msg = await event.reply("Bot Pong!")
    end = datetime.now()
    ms = (end - start).total_seconds() * 1000
    await reply_msg.edit(f"**Bot is On** \n\n __Pong__ !! `{ms:.3f}` ms")

# --- SUDO Management Commands --- (Using !, adjust prefix in help/Var.CMD_PREFIX)

CMD_PREFIX = Var.CMD_PREFIX if hasattr(Var, 'CMD_PREFIX') else "/" # Use '/' if not defined

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}addsudo(?: |$)"))
async def add_sudo(event):
    if event.sender_id not in SUDO_USERS: return
    user_id_to_add, target_user = await get_user_id_from_event(event)
    if not user_id_to_add: return
    if user_id_to_add in SUDO_USERS:
        await event.reply(f"User `{user_id_to_add}` is already SUDO.")
        return
    SUDO_USERS.add(user_id_to_add)
    DYNAMIC_SUDO_USERS.add(user_id_to_add)
    try:
        with open(SUDO_FILE, 'a') as f: f.write(f"{user_id_to_add}\n")
        logger.info(f"User {user_id_to_add} added to SUDO by {event.sender_id}.")
        name = f"User `{user_id_to_add}`"
        if target_user: name = f"[{get_display_name(target_user)}](tg://user?id={user_id_to_add})"
        await event.reply(f"✅ {name} added to SUDO.", parse_mode='md')
    except Exception as e:
        logger.error(f"Failed write to {SUDO_FILE}: {e}")
        SUDO_USERS.discard(user_id_to_add)
        DYNAMIC_SUDO_USERS.discard(user_id_to_add)
        await event.reply(f"❌ Failed to add to {SUDO_FILE}: {e}")

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}delsudo(?: |$)"))
async def del_sudo(event):
    if event.sender_id not in SUDO_USERS: return
    user_id_to_del, target_user = await get_user_id_from_event(event)
    if not user_id_to_del: return
    if user_id_to_del not in SUDO_USERS:
        await event.reply(f"User `{user_id_to_del}` is not SUDO.")
        return
    if user_id_to_del in CORE_SUDO_USERS:
         await event.reply(f"User `{user_id_to_del}` is a core SUDO user (from Var) and cannot be removed via command.")
         return
    SUDO_USERS.discard(user_id_to_del)
    DYNAMIC_SUDO_USERS.discard(user_id_to_del)
    try:
        # Rewrite the file without the user
        with open(SUDO_FILE, 'w') as f:
            for uid in DYNAMIC_SUDO_USERS: f.write(f"{uid}\n")
        logger.info(f"User {user_id_to_del} removed from SUDO by {event.sender_id}.")
        name = f"User `{user_id_to_del}`"
        if target_user: name = f"[{get_display_name(target_user)}](tg://user?id={user_id_to_del})"
        await event.reply(f"✅ {name} removed from SUDO.", parse_mode='md')
    except Exception as e:
        logger.error(f"Failed update {SUDO_FILE}: {e}")
        # Rollback runtime removal
        SUDO_USERS.add(user_id_to_del)
        DYNAMIC_SUDO_USERS.add(user_id_to_del)
        await event.reply(f"❌ Failed to remove from {SUDO_FILE}: {e}")


# --- Action Command Implementation (Generic) ---

async def execute_mass_action(event, action_type, client_to_use, is_bot_client):
    """Generic function to handle banall, kickall, unbanall."""
    sender_id = event.sender_id
    if sender_id not in SUDO_USERS: return

    if not is_bot_client and sender_id not in user_clients:
        await event.reply("You need to be logged in first using /login to use user actions.")
        return

    target_chat_id = await get_target_chat_id(event, client_to_use)
    if not target_chat_id: return

    required_permission = 'ban' if 'ban' in action_type else 'kick'
    if not await check_client_permissions(event, client_to_use, target_chat_id, [required_permission]):
        client_name = "Bot" if is_bot_client else f"User `{sender_id}`"
        # Error message already sent by check_client_permissions
        # await event.reply(f"{client_name} lacks necessary permissions in the target chat.")
        return

    # Determine action specifics
    if action_type == "banall":
        action_name = "Banning"
        rights = BAN_RIGHTS
        filter_type = None # Iterate all participants
        success_verb = "Banned"
    elif action_type == "kickall":
        action_name = "Kicking"
        rights = None # Not applicable for kick_participant
        filter_type = None # Iterate all participants
        success_verb = "Kicked"
    elif action_type == "unbanall":
        action_name = "Unbanning"
        rights = UNBAN_RIGHTS
        filter_type = types.ChannelParticipantsKicked # Iterate banned
        success_verb = "Unbanned"
    else:
        await event.reply("Internal error: Unknown action type.")
        return

    status_message = await event.reply(f"{action_name} members in chat `{target_chat_id}`...")
    if hasattr(event, 'delete'): await event.delete() # Delete command if possible

    try:
        me = await client_to_use.get_me()
        admin_ids = set()
        if action_type != "unbanall": # No need to check admins when unbanning
            admins = await client_to_use.get_participants(target_chat_id, filter=types.ChannelParticipantsAdmins)
            admin_ids = {admin.id for admin in admins}
            admin_ids.add(me.id) # Ensure client doesn't action itself

        processed_count = 0
        error_count = 0
        total_checked = 0

        async for user in client_to_use.iter_participants(target_chat_id, filter=filter_type, aggressive=(filter_type is not None)):
            total_checked += 1
            # Skip admins/bots only if banning/kicking
            if action_type != "unbanall" and (user.id in admin_ids or user.bot):
                continue

            # Skip self if somehow missed in admin check (shouldn't happen for ban/kick)
            if user.id == me.id:
                 continue

            try:
                if action_type == "kickall":
                    await client_to_use.kick_participant(target_chat_id, user.id)
                else: # banall or unbanall
                    await client_to_use(EditBannedRequest(target_chat_id, user.id, rights))

                processed_count += 1
                logger.info(f"{success_verb} user {user.id} from {target_chat_id} by client {me.id}")
                await asyncio.sleep(ACTION_SLEEP_INTERVAL if action_type != "unbanall" else ACTION_SLEEP_INTERVAL / 2)

            except FloodWaitError as fwe:
                logger.warning(f"Flood wait ({fwe.seconds}s) for client {me.id} during {action_type}")
                await status_message.edit(f"{action_name}... Flood wait: Sleeping for {fwe.seconds}s...")
                await asyncio.sleep(fwe.seconds + 5)
                # Optional: Retry the last failed action here? Could get complex.
            except (UserAdminInvalidError, UserCreatorError):
                logger.warning(f"Skipping admin/creator {user.id} during {action_type} by {me.id}.")
                if action_type != "unbanall": admin_ids.add(user.id) # Add to known admins
                error_count += 1
            except (ChatAdminRequiredError, ChatWriteForbiddenError):
                logger.error(f"Client {me.id} lost permissions during {action_type} in {target_chat_id}.")
                await status_message.edit(f"Error: Client `{me.id}` lost required permissions.")
                return
            except UserNotParticipantError:
                 logger.warning(f"User {user.id} not participant during {action_type} by {me.id}.")
                 error_count +=1
            except (UserIdInvalidError, PeerIdInvalidError):
                 logger.warning(f"Invalid user ID {user.id} encountered by {me.id}.")
                 error_count += 1
            except Exception as e:
                logger.error(f"Failed to {action_type.replace('all','')} {user.id} by {me.id}: {type(e).__name__}: {e}")
                error_count += 1
                await asyncio.sleep(ACTION_SLEEP_INTERVAL) # Still sleep on other errors

        final_message = (f"**{action_name.replace('ing','')} All Complete!** (Chat: `{target_chat_id}`)\n\n"
                         f"**{success_verb}:** `{processed_count}`\n"
                         f"**Skipped/Errors:** `{error_count}`\n")
        if filter_type is None: # Only show total checked if iterating all
            final_message += f"**Total Checked (approx):** `{total_checked}`"
        await status_message.edit(final_message)

    except Exception as e:
        logger.exception(f"An unexpected error occurred during {action_type} loop for {target_chat_id}")
        await status_message.edit(f"An unexpected error occurred: {e}")


# --- Bot Action Handlers --- (Requires Bot Admin)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}bbanall(?: |$)"))
async def bot_banall(event):
    await execute_mass_action(event, "banall", client, is_bot_client=True)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}bkickall(?: |$)"))
async def bot_kickall(event):
     await execute_mass_action(event, "kickall", client, is_bot_client=True)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}bunbanall(?: |$)"))
async def bot_unbanall(event):
     await execute_mass_action(event, "unbanall", client, is_bot_client=True)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}bleave(?: |$)(.*)"))
async def bot_leave(event):
    if event.sender_id not in SUDO_USERS: return
    target_chat_id_str = event.pattern_match.group(1)
    status_message = await event.reply("Processing bot leave command...")

    if target_chat_id_str:
        try: target_chat_id = await get_target_chat_id(event, client) # Use helper
        except ValueError: return # Error handled by helper
    else: # Leave current chat
        if not event.is_private and event.chat_id: target_chat_id = event.chat_id
        else:
            await status_message.edit("Use this command in the group/channel or provide its ID/Username.")
            return

    if not target_chat_id: return # Error handled by helper

    try:
        await client(LeaveChannelRequest(target_chat_id))
        logger.info(f"Bot successfully left chat {target_chat_id}")
        if target_chat_id != event.chat_id:
            await status_message.edit(f"Bot successfully left chat `{target_chat_id}`")
            await asyncio.sleep(3); await status_message.delete()
        else: # Can't edit message in chat bot just left
             pass # Maybe PM confirmation? See previous version's logic
    except (UserNotParticipantError, errors.ChatForbiddenError, errors.ChannelPrivateError):
         await status_message.edit(f"Bot is not in chat `{target_chat_id}` or cannot leave it.")
    except Exception as e:
        logger.error(f"Bot failed to leave chat {target_chat_id}: {e}")
        await status_message.edit(f"Error leaving chat `{target_chat_id}`: {type(e).__name__}")

# --- User Action Handlers --- (Requires User Logged In & User Admin)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}ubanall(?: |$)"))
async def user_banall(event):
    user_client = user_clients.get(event.sender_id)
    await execute_mass_action(event, "banall", user_client, is_bot_client=False)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}ukickall(?: |$)"))
async def user_kickall(event):
    user_client = user_clients.get(event.sender_id)
    await execute_mass_action(event, "kickall", user_client, is_bot_client=False)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}uunbanall(?: |$)"))
async def user_unbanall(event):
    user_client = user_clients.get(event.sender_id)
    await execute_mass_action(event, "unbanall", user_client, is_bot_client=False)

@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}uleave(?: |$)"))
async def user_leave(event):
    sender_id = event.sender_id
    if sender_id not in SUDO_USERS: return
    user_client = user_clients.get(sender_id)
    if not user_client:
        await event.reply("You need to be logged in first using /login.")
        return

    status_message = await event.reply("Processing user leave command...")
    target_chat_id = await get_target_chat_id(event, user_client)
    if not target_chat_id:
        await status_message.delete() # Clean up status message
        return

    try:
        me = await user_client.get_me()
        await user_client(LeaveChannelRequest(target_chat_id))
        logger.info(f"User {sender_id} ({get_display_name(me)}) successfully left chat {target_chat_id}")
        await status_message.edit(f"Your account (`{sender_id}`) successfully left chat `{target_chat_id}`.")
    except (UserNotParticipantError, errors.ChatForbiddenError, errors.ChannelPrivateError):
         await status_message.edit(f"Your account (`{sender_id}`) is not in chat `{target_chat_id}` or cannot leave it.")
    except Exception as e:
        logger.error(f"User {sender_id} failed to leave chat {target_chat_id}: {e}")
        await status_message.edit(f"Error leaving chat `{target_chat_id}` with your account: {type(e).__name__}")


# --- Bot Restart ---
@client.on(events.NewMessage(pattern=f"^{re.escape(CMD_PREFIX)}restart$"))
async def restart(event):
    if event.sender_id not in SUDO_USERS: return
    try: await event.reply("__Restarting bot... Logged in user sessions will be disconnected.__")
    except Exception as e: logger.error(f"Error sending restart confirmation: {e}")
    logger.info("Restart command received. Disconnecting clients...")

    # Disconnect user clients first
    for user_id, u_client in list(user_clients.items()): # Iterate over copy
        try:
            if u_client.is_connected(): await u_client.disconnect()
            logger.info(f"Disconnected client for user {user_id}")
        except Exception as e: logger.error(f"Error disconnecting client for user {user_id}: {e}")
        del user_clients[user_id] # Remove from active dict

    # Disconnect bot client
    try:
        if client.is_connected(): await client.disconnect()
        logger.info("Bot client disconnected.")
    except Exception as e: logger.error(f"Error during bot client disconnection: {e}")

    # Restart the script
    logger.info("Executing restart...")
    try: os.execl(sys.executable, sys.executable, *sys.argv)
    except Exception as e:
        logger.critical(f"!!! FAILED TO RESTART SCRIPT: {e} !!!")
        sys.exit(1)

# --- Main Execution ---
async def main():
    """Connects the bot and runs it."""
    try:
        # Connect the main bot client
        # Use bot_token for authentication
        await client.start(bot_token=Var.BOT_TOKEN)
        logger.info("Bot client started successfully.")

        # Optional: Attempt to reconnect logged-in user sessions on startup
        # This is complex due to potential auth issues after restart
        # Basic example (might need more robust error handling):
        # for session_file in os.listdir(USER_SESSIONS_DIR):
        #     if session_file.endswith(".session") and session_file.startswith("user_"):
        #         user_id_str = session_file.split('_')[1].split('.')[0]
        #         try:
        #             user_id = int(user_id_str)
        #             logger.info(f"Attempting to reconnect user {user_id} from session...")
        #             # Need API ID/Hash - cannot reliably get these after restart
        #             # This approach requires storing API ID/Hash securely, which is risky
        #             # Or, prompt users to /login again after restart.
        #         except ValueError: continue
        #         except Exception as e: logger.error(f"Failed reconnect for {user_id}: {e}")

        # Keep the bot running
        print("\n---------------------------------------")
        print(" MANAGER 𝐁𝐎𝐓 IS RUNNING")
        print(f" Command Prefix: {CMD_PREFIX}")
        print(f" Active SUDO Users: {SUDO_USERS}")
        print(" Ensure user_sessions/ directory exists.")
        print("---------------------------------------\n")
        await client.run_until_disconnected()

    except ApiIdInvalidError:
         logger.critical("Bot's API ID or Hash is invalid. Please check var.py.")
    except Exception as e:
        logger.exception("Critical error during bot startup or runtime.")
    finally:
        # Cleanup on exit
        logger.info("Disconnecting remaining clients...")
        for user_id, u_client in user_clients.items():
            if u_client.is_connected(): await u_client.disconnect()
        if client.is_connected(): await client.disconnect()
        logger.info("Bot shutdown complete.")


if __name__ == '__main__':
    # Use asyncio.run() to start the main asynchronous function
    asyncio.run(main())

