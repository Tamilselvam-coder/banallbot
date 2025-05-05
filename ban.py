import logging
import re
import os
import sys
import asyncio
from telethon import TelegramClient, events, functions, types, errors
from telethon.tl.types import (
    ChannelParticipantsAdmins,
    ChannelParticipantsKicked,
    ChatBannedRights,
    UserStatusEmpty,
    UserStatusLastMonth,
    UserStatusLastWeek,
    UserStatusOffline,
    UserStatusOnline,
    UserStatusRecently,
)
from telethon.tl.functions.channels import (
    LeaveChannelRequest,
    EditBannedRequest,
    GetParticipantRequest # To check bot's own permissions if needed
)
from telethon.errors.rpcerrorlist import (
    FloodWaitError,
    UserAdminInvalidError,
    ChatAdminRequiredError,
    UserNotParticipantError,
    ChatWriteForbiddenError,
    UserCreatorError,
    UserIdInvalidError
)

from datetime import datetime
from time import sleep # Keep synchronous sleep for FloodWaitError in unbanall if preferred
from var import Var # Assuming var.py contains API_ID, API_HASH, BOT_TOKEN, SUDO

# --- Constants ---
# Permissions needed for a full ban (True = Restricted)
BAN_RIGHTS = ChatBannedRights(
    until_date=None, # Permanent ban
    view_messages=True,
    send_messages=True,
    send_media=True,
    send_stickers=True,
    send_gifs=True,
    send_games=True,
    send_inline=True,
    embed_links=True,
)

# Permissions needed to unban (False = Allowed)
UNBAN_RIGHTS = ChatBannedRights(
    until_date=None, # Set until_date=0 or None in the request itself
    view_messages=False,
    # All other rights default to False (allowed)
)

# Basic sleep time between actions to be gentler on API
ACTION_SLEEP_INTERVAL = 0.8 # seconds

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

print("Starting Daxx BanAll Bot.....")

# Initialize Telegram Client
try:
    client = TelegramClient(
        'DaxxSession', # Use a descriptive session name
        Var.API_ID,
        Var.API_HASH
    ).start(bot_token=Var.BOT_TOKEN)
except Exception as e:
    logger.critical(f"Failed to initialize Telegram Client: {e}")
    sys.exit(1)

# Load Sudo Users
SUDO_USERS = []
try:
    for user_id in Var.SUDO:
        SUDO_USERS.append(int(user_id)) # Ensure they are integers
    logger.info(f"Sudo users loaded: {SUDO_USERS}")
except AttributeError:
    logger.warning("Var.SUDO not found or invalid in var.py. No sudo users loaded.")
except ValueError:
    logger.warning("Var.SUDO contains non-integer values. Check var.py.")

# --- Helper Function ---
async def check_permissions(event, rights_needed):
    """Checks if the bot has the necessary admin rights in the chat."""
    try:
        chat = await event.get_chat()
        me = await client.get_me()
        # In channels/supergroups, check permissions directly
        if hasattr(chat, 'admin_rights'):
            permissions = await client.get_permissions(chat, me)
            if not permissions.is_admin:
                 await event.reply("I'm not an admin here!")
                 return False, None # Not admin

            missing_rights = []
            if 'ban' in rights_needed and not permissions.ban_users:
                missing_rights.append("ban users")
            if 'kick' in rights_needed and not permissions.kick_users:
                missing_rights.append("kick users")

            if missing_rights:
                await event.reply(f"I lack the permission to: {', '.join(missing_rights)}.")
                return False, None

            return True, chat # Has necessary rights
        else:
            # Basic group, admin rights might work differently or not apply
            # Check if bot is creator? Or just assume it works if basic checks pass.
            # For simplicity, assume if it's a group and we got this far, basic rights exist.
            # A more robust check might be needed for legacy groups.
            # Check if we are creator here?
            if not chat.creator and (not chat.admin_rights or (('ban' in rights_needed and not chat.admin_rights.ban_users) or ('kick' in rights_needed and not chat.admin_rights.kick_users))):
                 await event.reply(f"I lack the required admin permissions in this group.")
                 return False, None

            return True, chat


    except (ChatAdminRequiredError, ChannelPrivateError): # Might not have rights to even get_permissions
        await event.reply("I don't seem to have basic admin rights or access to this chat's permissions.")
        return False, None
    except Exception as e:
        logger.error(f"Error checking permissions: {e}")
        await event.reply(f"An error occurred while checking permissions: {e}")
        return False, None


# --- Event Handlers ---

@client.on(events.NewMessage(pattern="^/ping", from_users=SUDO_USERS))
async def ping(event):
    start = datetime.now()
    reply_msg = await event.reply("Pong!")
    end = datetime.now()
    ms = (end - start).total_seconds() * 1000
    await reply_msg.edit(f"**I'm On** \n\n __Pong__ !! `{ms:.3f}` ms")


@client.on(events.NewMessage(pattern="^/kickall", from_users=SUDO_USERS))
async def kickall(event):
    if not event.is_group:
        await event.reply("Use this command in a group or channel.")
        return

    has_perms, chat = await check_permissions(event, ['kick'])
    if not has_perms:
        return

    status_message = await event.reply(" Kicking all non-admin members...")
    await event.delete() # Delete the command message

    admins = await client.get_participants(chat, filter=types.ChannelParticipantsAdmins)
    admin_ids = {admin.id for admin in admins}
    me_id = (await client.get_me()).id
    admin_ids.add(me_id) # Ensure bot doesn't kick itself

    total_users = 0
    kicked_count = 0
    error_count = 0

    try:
        async for user in client.iter_participants(chat):
            total_users += 1
            if user.id in admin_ids or user.is_bot: # Skip admins and bots
                continue

            try:
                # Use kick_participant for a simpler kick
                await client.kick_participant(chat.id, user.id)
                kicked_count += 1
                logger.info(f"Kicked user {user.id} from {chat.id}")
                await asyncio.sleep(ACTION_SLEEP_INTERVAL) # Sleep between kicks

            except FloodWaitError as fwe:
                logger.warning(f"Flood wait of {fwe.seconds} seconds triggered during kickall.")
                await status_message.edit(f"Flood wait: Sleeping for {fwe.seconds} seconds...")
                await asyncio.sleep(fwe.seconds + 5) # Sleep requested time + buffer
                # Retry kicking the same user after flood wait
                try:
                    await client.kick_participant(chat.id, user.id)
                    kicked_count += 1
                    logger.info(f"Kicked user {user.id} after flood wait.")
                except Exception as retry_e:
                    logger.error(f"Failed to kick {user.id} after flood wait: {retry_e}")
                    error_count += 1
            except (UserAdminInvalidError, UserCreatorError):
                logger.warning(f"Skipping admin/creator {user.id} during kickall.")
                admin_ids.add(user.id) # Add to known admins if missed
            except (ChatAdminRequiredError, ChatWriteForbiddenError):
                logger.error("Lost kick permissions during kickall operation.")
                await status_message.edit("Error: Lost admin rights to kick users.")
                return
            except UserNotParticipantError:
                 logger.warning(f"User {user.id} already left or was removed.")
                 error_count +=1 # Or just ignore
            except Exception as e:
                logger.error(f"Failed to kick {user.id}: {type(e).__name__}: {e}")
                error_count += 1
                await asyncio.sleep(ACTION_SLEEP_INTERVAL) # Still sleep on other errors


        final_message = (f"**Kickall Complete!**\n\n"
                         f"**Kicked:** `{kicked_count}`\n"
                         f"**Skipped/Errors:** `{error_count}`\n"
                         f"**Total Checked (approx):** `{total_users}`") # iter_participants count might be approximate
        await status_message.edit(final_message)

    except Exception as e:
        logger.exception("An unexpected error occurred during /kickall loop.")
        await status_message.edit(f"An unexpected error occurred: {e}")


@client.on(events.NewMessage(pattern="^/banall", from_users=SUDO_USERS))
async def banall(event):
    if not event.is_group:
        await event.reply("Use this command in a group or channel.")
        return

    has_perms, chat = await check_permissions(event, ['ban'])
    if not has_perms:
        return

    status_message = await event.reply(" Banning all non-admin members...")
    await event.delete()

    admins = await client.get_participants(chat, filter=types.ChannelParticipantsAdmins)
    admin_ids = {admin.id for admin in admins}
    me_id = (await client.get_me()).id
    admin_ids.add(me_id) # Ensure bot doesn't ban itself

    total_users = 0
    banned_count = 0
    error_count = 0

    try:
        async for user in client.iter_participants(chat):
            total_users += 1
            if user.id in admin_ids or user.is_bot: # Skip admins and bots
                continue

            try:
                await client(EditBannedRequest(chat.id, user.id, BAN_RIGHTS))
                banned_count += 1
                logger.info(f"Banned user {user.id} from {chat.id}")
                await asyncio.sleep(ACTION_SLEEP_INTERVAL) # Sleep between bans

            except FloodWaitError as fwe:
                logger.warning(f"Flood wait of {fwe.seconds} seconds triggered during banall.")
                await status_message.edit(f"Flood wait: Sleeping for {fwe.seconds} seconds...")
                await asyncio.sleep(fwe.seconds + 5) # Sleep requested time + buffer
                # Retry banning the same user after flood wait
                try:
                    await client(EditBannedRequest(chat.id, user.id, BAN_RIGHTS))
                    banned_count += 1
                    logger.info(f"Banned user {user.id} after flood wait.")
                except Exception as retry_e:
                    logger.error(f"Failed to ban {user.id} after flood wait: {retry_e}")
                    error_count += 1
            except (UserAdminInvalidError, UserCreatorError):
                logger.warning(f"Skipping admin/creator {user.id} during banall.")
                admin_ids.add(user.id) # Add to known admins if missed
            except (ChatAdminRequiredError, ChatWriteForbiddenError):
                logger.error("Lost ban permissions during banall operation.")
                await status_message.edit("Error: Lost admin rights to ban users.")
                return
            except UserNotParticipantError:
                 logger.warning(f"User {user.id} already left or was removed before banning.")
                 error_count +=1 # Or just ignore
            except UserIdInvalidError:
                 logger.warning(f"Invalid user ID {user.id} encountered.")
                 error_count += 1
            except Exception as e:
                logger.error(f"Failed to ban {user.id}: {type(e).__name__}: {e}")
                error_count += 1
                await asyncio.sleep(ACTION_SLEEP_INTERVAL) # Still sleep on other errors


        final_message = (f"**Banall Complete!**\n\n"
                         f"**Banned:** `{banned_count}`\n"
                         f"**Skipped/Errors:** `{error_count}`\n"
                         f"**Total Checked (approx):** `{total_users}`")
        await status_message.edit(final_message)

    except Exception as e:
        logger.exception("An unexpected error occurred during /banall loop.")
        await status_message.edit(f"An unexpected error occurred: {e}")


@client.on(events.NewMessage(pattern="^/unbanall", from_users=SUDO_USERS))
async def unbanall(event):
    if not event.is_group:
        await event.reply("Use this command in a group or channel.")
        return

    # Check for ban permissions as unbanning requires the same right
    has_perms, chat = await check_permissions(event, ['ban'])
    if not has_perms:
        return

    status_message = await event.reply(" Searching and unbanning users...")
    unbanned_count = 0
    error_count = 0

    try:
        # Iterate through kicked/banned participants
        # aggressive=True fetches faster but uses more RAM, okay for this usually
        async for user in client.iter_participants(
            chat.id, filter=types.ChannelParticipantsKicked, aggressive=True
        ):
            try:
                # Define unban rights locally for clarity
                unban_rights = ChatBannedRights(until_date=0, view_messages=False)
                await client(EditBannedRequest(chat.id, user.id, unban_rights))
                unbanned_count += 1
                logger.info(f"Unbanned user {user.id} from {chat.id}")
                # Use synchronous sleep here if preferred as in original, or asyncio
                await asyncio.sleep(ACTION_SLEEP_INTERVAL / 2) # Can often unban faster

            except FloodWaitError as fwe:
                logger.warning(f"Flood wait of {fwe.seconds} seconds triggered during unbanall.")
                await status_message.edit(f"Flood wait: Sleeping for {fwe.seconds} seconds...")
                # Use sync sleep if you prefer it for flood waits specifically
                sleep(fwe.seconds + 5) # Sleep requested time + buffer
                 # No retry needed here as the loop will eventually get back
            except (ChatAdminRequiredError, ChatWriteForbiddenError):
                logger.error("Lost ban/unban permissions during unbanall operation.")
                await status_message.edit("Error: Lost admin rights to unban users.")
                return
            except UserAdminInvalidError:
                logger.error(f"Tried to unban an admin/creator {user.id}? This shouldn't happen with ChannelParticipantsKicked filter.")
                error_count += 1
            except Exception as e:
                logger.error(f"Failed to unban {user.id}: {type(e).__name__}: {e}")
                error_count += 1
                await asyncio.sleep(ACTION_SLEEP_INTERVAL / 2)

        final_message = (f"**Unban All Complete!**\n\n"
                         f"**Unbanned:** `{unbanned_count}`\n"
                         f"**Errors:** `{error_count}`")
        await status_message.edit(final_message)

    except Exception as e:
        logger.exception("An unexpected error occurred during /unbanall loop.")
        await status_message.edit(f"An unexpected error occurred: {e}")


@client.on(events.NewMessage(pattern="^/leave(?: |$)(.*)", from_users=SUDO_USERS))
async def leave(event):
    target_chat_id_str = event.pattern_match.group(1)
    status_message = await event.reply("Processing leave command...")

    if target_chat_id_str:
        try:
            target_chat_id = int(target_chat_id_str)
            logger.info(f"Attempting to leave chat ID: {target_chat_id}")
        except ValueError:
            await status_message.edit("Invalid Chat ID provided. Please provide an integer ID.")
            return
    else:
        # Leave current chat if no ID is given
        if not event.is_private and event.chat_id:
            target_chat_id = event.chat_id
            logger.info(f"Attempting to leave current chat: {target_chat_id}")
        else:
            await status_message.edit("Use this command in the chat you want to leave, or provide the chat ID.")
            return

    try:
        await client(LeaveChannelRequest(target_chat_id))
        logger.info(f"Successfully left chat {target_chat_id}")
        await status_message.edit(f"Successfully left chat `{target_chat_id}`")
        # Can't edit message if we left the chat it was in, unless it's the same chat
        if target_chat_id == event.chat_id:
             # No further edits possible here
             pass
        else:
            await asyncio.sleep(3) # Give time to read message before deleting maybe?
            await status_message.delete() # Delete confirmation in original chat

    except errors.UserNotParticipantError:
         await status_message.edit(f"I am not currently in chat `{target_chat_id}`.")
    except errors.ChannelPrivateError:
         await status_message.edit(f"Could not leave chat `{target_chat_id}`. Maybe it's a private channel I can't access or leave?")
    except Exception as e:
        logger.error(f"Failed to leave chat {target_chat_id}: {e}")
        await status_message.edit(f"Error leaving chat `{target_chat_id}`: {type(e).__name__}")


@client.on(events.NewMessage(pattern="^/restart", from_users=SUDO_USERS))
async def restart(event):
    # Send confirmation message first, because the script will stop execution
    try:
        await event.reply("__Restarting bot...__")
    except Exception as e:
        logger.error(f"Error sending restart confirmation: {e}")

    logger.info("Restart command received. Attempting to restart...")

    try:
        # Gracefully disconnect the client
        await client.disconnect()
        logger.info("Telegram client disconnected.")
    except Exception as e:
        logger.error(f"Error during client disconnection: {e}")
        # Continue with restart anyway

    # Restart the script
    # os.execl replaces the current process with the new one
    try:
        os.execl(sys.executable, sys.executable, *sys.argv)
    except Exception as e:
        logger.critical(f"!!! FAILED TO RESTART SCRIPT: {e} !!!")
        # If execl fails, we might need to exit manually
        sys.exit(1) # Exit with error code


# --- Start the Bot ---
if __name__ == '__main__':
    print("\n---------------------------------------")
    print("𝐃𝐀𝐗𝐗 𝐓𝐄𝐀𝐌 𝐁𝐀𝐍 𝐀𝐋𝐋 𝐁𝐎𝐓 IS RUNNING")
    print("---------------------------------------\n")
    client.run_until_disconnected()
    print("\nBot disconnected.")
