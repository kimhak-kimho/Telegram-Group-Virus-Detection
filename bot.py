"""
bot.py — Telegram Group Virus Detection Bot.

Fast-blocks dangerous types from metadata (no download). Allowed files
are downloaded and scanned with ClamAV.

Run with:  python bot.py
(TELEGRAM_BOT_TOKEN must be set in the environment or a .env file.)
"""

from __future__ import annotations

import logging
import time

from typing import Optional

from telegram import Chat, Message, Update
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.error import BadRequest, Forbidden, TelegramError, TimedOut
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import database
import messages
import scanner
from config import CONFIG, validate_config

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("virus_bot")

START_TIME = time.time()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


async def is_group_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat = update.effective_chat
    if user is None or chat is None:
        return False
    if user.id in CONFIG.super_admin_ids:
        return True
    if chat.type == Chat.PRIVATE:
        return True
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
    except TelegramError:
        return False
    return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)


def extension_display(exts: list[str]) -> str:
    return ", ".join(sorted(exts)) if exts else "(គ្មាន)"


def _delete_note(deleted: bool) -> str:
    return messages.delete_note(deleted)


def forward_origin_label(message: Message) -> Optional[str]:
    """Return a display name if this message was forwarded, else None."""
    origin = getattr(message, "forward_origin", None)
    if origin is not None:
        sender_user = getattr(origin, "sender_user", None)
        if sender_user is not None:
            return sender_user.full_name or sender_user.username or str(sender_user.id)
        hidden_name = getattr(origin, "sender_user_name", None)
        if hidden_name:
            return hidden_name
        chat = getattr(origin, "sender_chat", None) or getattr(origin, "chat", None)
        if chat is not None:
            return chat.title or chat.username or str(chat.id)
        return "Forwarded"
    if getattr(message, "forward_date", None) or getattr(message, "forward_from", None) or getattr(
        message, "forward_from_chat", None
    ):
        chat = getattr(message, "forward_from_chat", None)
        user = getattr(message, "forward_from", None)
        if chat is not None:
            return chat.title or chat.username or str(chat.id)
        if user is not None:
            return user.full_name or user.username or str(user.id)
        return "Forwarded"
    return None


# ---------------------------------------------------------------------------
# Core scanning workflow — shared by the automatic handler and /scan
# ---------------------------------------------------------------------------

async def process_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    message: Message,
) -> None:
    document = message.document
    if document is None:
        return

    chat_id = message.chat_id
    user_id = message.from_user.id if message.from_user else None
    original_name = document.file_name or "unnamed_file"
    display_name = scanner.sanitize_filename(original_name)
    ext = scanner.get_extension(display_name)
    file_size = document.file_size or 0
    mime_type = document.mime_type or "unknown"

    settings = database.get_group_settings(chat_id)
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    fwd_from = forward_origin_label(message)

    reason = scanner.blocked_reason(
        display_name,
        document.mime_type,
        settings.blocked_extensions,
        settings.extension_blocking_enabled,
    )
    if reason:
        kind, value = reason
        deleted = await _try_delete(message, context)
        reason_html = messages.reason_text(kind, value)
        database.log_scan(
            chat_id, user_id, display_name, file_size,
            result="blocked_extension",
            action_taken="deleted" if deleted else "kept_no_permission",
            signature=f"{kind}:{value}",
        )
        await context.bot.send_message(
            chat_id,
            messages.blocked_file(
                display_name,
                human_size(file_size),
                reason_html,
                _delete_note(deleted),
                fwd_from,
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    if file_size > max_bytes:
        deleted = await _try_delete(message, context)
        database.log_scan(
            chat_id, user_id, display_name, file_size,
            result="too_large",
            action_taken="deleted" if deleted else "rejected_no_download",
        )
        note = _delete_note(deleted)
        await context.bot.send_message(
            chat_id,
            messages.too_large(
                display_name, human_size(file_size), settings.max_file_size_mb, note
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await context.bot.send_message(chat_id, messages.SCANNING)
    temp_path: Optional[str] = None
    try:
        tg_file = await context.bot.get_file(document.file_id)
        temp_path = scanner.make_temp_path(ext)
        await tg_file.download_to_drive(custom_path=temp_path)
        result = await scanner.scan_file(temp_path)

        if result.outcome == scanner.ScanOutcome.SAFE:
            database.log_scan(
                chat_id, user_id, display_name, file_size,
                result="safe", action_taken="kept",
            )
            await status_msg.edit_text(
                messages.allowed(
                    display_name, human_size(file_size), ext or "none", mime_type
                ),
                parse_mode=ParseMode.HTML,
            )

        elif result.outcome == scanner.ScanOutcome.INFECTED:
            deleted = await _try_delete(message, context)
            database.log_scan(
                chat_id, user_id, display_name, file_size,
                result="infected",
                action_taken="deleted" if deleted else "kept_no_permission",
                signature=result.signature,
            )
            await status_msg.edit_text(
                messages.infected(
                    display_name, result.signature or "unknown", _delete_note(deleted)
                ),
                parse_mode=ParseMode.HTML,
            )

        else:
            database.log_scan(
                chat_id, user_id, display_name, file_size,
                result="error", action_taken="kept", signature=result.detail,
            )
            logger.warning("Scan failed for %s in chat %s: %s", display_name, chat_id, result.detail)
            await status_msg.edit_text(
                messages.VERIFY_FAIL_SCANNER,
                parse_mode=ParseMode.HTML,
            )

    except (TimedOut, TelegramError) as exc:
        database.log_scan(
            chat_id, user_id, display_name, file_size,
            result="error", action_taken="kept", signature=str(exc),
        )
        logger.exception("Telegram error while handling file %s", display_name)
        await status_msg.edit_text(
            messages.VERIFY_FAIL_NETWORK,
            parse_mode=ParseMode.HTML,
        )
    finally:
        if temp_path:
            scanner.cleanup_temp_file(temp_path)


async def _try_delete(message: Message, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        await message.delete()
        return True
    except (BadRequest, Forbidden) as exc:
        logger.warning(
            "Could not delete message %s in chat %s: %s",
            message.message_id, message.chat_id, exc,
        )
        return False


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message is None or update.message.document is None:
        return
    await process_document(update, context, update.message)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(messages.START, parse_mode=ParseMode.HTML)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(messages.HELP, parse_mode=ParseMode.HTML)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    settings = database.get_group_settings(chat_id)
    clamav_ok = await scanner.is_clamav_available()
    uptime_s = int(time.time() - START_TIME)
    uptime = f"{uptime_s // 3600}h {(uptime_s % 3600) // 60}m {uptime_s % 60}s"

    await update.message.reply_text(
        messages.status(
            uptime,
            clamav_ok,
            settings.max_file_size_mb,
            settings.extension_blocking_enabled,
            extension_display(settings.blocked_extensions),
            extension_display(sorted(scanner.HARD_DANGEROUS_EXTENSIONS)),
        ),
        parse_mode=ParseMode.HTML,
    )


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    replied = update.message.reply_to_message
    if replied is None or replied.document is None:
        await update.message.reply_text(messages.SCAN_REPLY_HINT)
        return
    await process_document(update, context, replied)


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    s = database.get_stats(chat_id)
    await update.message.reply_text(
        messages.stats(
            s.total, s.safe, s.infected, s.errors, s.blocked_extension, s.too_large
        ),
        parse_mode=ParseMode.HTML,
    )


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    settings = database.get_group_settings(chat_id)
    args = context.args or []

    if not args:
        await update.message.reply_text(
            messages.current_settings(
                settings.max_file_size_mb,
                settings.extension_blocking_enabled,
                extension_display(settings.blocked_extensions),
                extension_display(sorted(scanner.HARD_DANGEROUS_EXTENSIONS)),
            ),
            parse_mode=ParseMode.HTML,
        )
        return

    if not await is_group_admin(update, context):
        await update.message.reply_text(messages.NOT_ADMIN)
        return

    sub = args[0].lower()

    if sub == "maxsize" and len(args) == 2:
        try:
            mb = int(args[1])
        except ValueError:
            await update.message.reply_text(messages.MAXSIZE_USAGE, parse_mode=ParseMode.HTML)
            return
        if mb <= 0 or mb > CONFIG.hard_max_file_size_mb:
            await update.message.reply_text(messages.maxsize_range(CONFIG.hard_max_file_size_mb))
            return
        settings.max_file_size_mb = mb
        database.save_group_settings(settings)
        await update.message.reply_text(messages.maxsize_set(mb))

    elif sub == "blocklist" and len(args) == 2 and args[1].lower() in ("on", "off"):
        settings.extension_blocking_enabled = args[1].lower() == "on"
        database.save_group_settings(settings)
        await update.message.reply_text(
            messages.blocklist_set(settings.extension_blocking_enabled),
            parse_mode=ParseMode.HTML,
        )

    elif sub == "addext" and len(args) == 2:
        ext = args[1].lower()
        if not ext.startswith("."):
            ext = "." + ext
        if ext not in settings.blocked_extensions:
            settings.blocked_extensions.append(ext)
            database.save_group_settings(settings)
        await update.message.reply_text(messages.ext_added(ext), parse_mode=ParseMode.HTML)

    elif sub == "removeext" and len(args) == 2:
        ext = args[1].lower()
        if not ext.startswith("."):
            ext = "." + ext
        if ext in scanner.HARD_DANGEROUS_EXTENSIONS:
            await update.message.reply_text(
                messages.ext_always_blocked(ext),
                parse_mode=ParseMode.HTML,
            )
            return
        if ext in settings.blocked_extensions:
            settings.blocked_extensions.remove(ext)
            database.save_group_settings(settings)
        await update.message.reply_text(messages.ext_removed(ext), parse_mode=ParseMode.HTML)

    else:
        await update.message.reply_text(messages.SETTINGS_USAGE)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Unhandled exception while processing update %s", update, exc_info=context.error)


async def _post_init(application: Application) -> None:
    clamav_ok = await scanner.is_clamav_available()
    if clamav_ok:
        logger.info("ClamAV daemon is reachable at %s:%s", CONFIG.clamav_host, CONFIG.clamav_port)
    else:
        logger.error(
            "ClamAV daemon is NOT reachable at %s:%s — allowed files will not be marked safe.",
            CONFIG.clamav_host, CONFIG.clamav_port,
        )


def main() -> None:
    problems = validate_config()
    if problems:
        for p in problems:
            logger.error("Config problem: %s", p)
        raise SystemExit(1)

    database.init_db()

    application = (
        Application.builder()
        .token(CONFIG.bot_token)
        .connect_timeout(CONFIG.telegram_connect_timeout)
        .read_timeout(CONFIG.telegram_read_timeout)
        .write_timeout(CONFIG.telegram_read_timeout)
        .pool_timeout(10)
        .get_updates_connect_timeout(CONFIG.telegram_connect_timeout)
        .get_updates_read_timeout(30)
        .post_init(_post_init)
        .build()
    )

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("scan", cmd_scan))
    application.add_handler(CommandHandler("stats", cmd_stats))
    application.add_handler(CommandHandler("settings", cmd_settings))
    application.add_handler(MessageHandler(filters.Document.ALL, on_document))
    application.add_error_handler(on_error)

    logger.info("Starting bot (fast-block + ClamAV for allowed files)...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
