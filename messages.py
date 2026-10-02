"""Khmer-only user-facing text for the Telegram bot."""

from __future__ import annotations

import html

HTML = "HTML"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def reason_text(kind: str, value: str) -> str:
    v = f"<code>{esc(value)}</code>"
    if kind == "archive":
        return f"ប្រភេទ {v} (ឯកសារបង្កប់)"
    if kind == "executable":
        return f"ប្រភេទ {v} (កម្មវិធី / ឯកសារដំឡើង)"
    if kind == "policy":
        return f"ប្រភេទ {v} (ហាមតាមគោលការណ៍ក្រុម)"
    if kind == "mime_archive":
        return f"ប្រភេទ MIME {v} (ឯកសារបង្កប់)"
    if kind == "mime_exe":
        return f"ប្រភេទ MIME {v} (កម្មវិធី)"
    return v


def delete_note(deleted: bool) -> str:
    if deleted:
        return ""
    return (
        "\n⚠️ មិនអាចលុបសារបានទេ — សូមលុបដោយដៃ "
        "ហើយពិនិត្យសិទ្ធិអ្នកគ្រប់គ្រងរបស់ Bot។"
    )


START = (
    "👋 <b>Security Bot</b>\n\n"
    "បន្ថែមខ្ញុំជាអ្នកគ្រប់គ្រងក្រុម (មានសិទ្ធិលុបសារ)។\n\n"
    "• ប្រភេទគ្រោះថ្នាក់ (<code>.exe</code>, <code>.js</code>, <code>.rar</code>, "
    "<code>.zip</code>, <code>.z</code>, …) ត្រូវបានទប់ស្កាត់ និងលុបភ្លាមៗ — មិនទាញយកទេ។\n"
    "• ឯកសារអនុញ្ញាត (រូបថត, PDF, Word, …) ត្រូវបានទាញយក និងស្កេនដោយ ClamAV។ "
    "ឯកសារស្អាតរក្សាទុក។ ឯកសារមានមេរោគត្រូវលុប។ "
    "បើស្កេនបរាជ័យ ខ្ញុំនឹង<b>មិន</b>និយាយថាឯកសារនេះមានសុវត្ថិភាពទេ។\n"
    "• ឯកសារ <b>Forwarded from</b> ដែលត្រូវបានទប់ស្កាត់ នឹងបង្ហាញនៅ "
    "<b>មូលហេតុ</b>៖ ⚠️ file Forwarded from: …\n\n"
    "ប្រើ /help ដើម្បីមើលពាក្យបញ្ជា។"
)

HELP = (
    "<b>ពាក្យបញ្ជា</b>\n"
    "/start — សេចក្ដីណែនាំ\n"
    "/help — សារនេះ\n"
    "/status — ស្ថានភាព Bot និងច្បាប់\n"
    "/scan — ឆ្លើយតបឯកសារដើម្បីស្កេនម្ដងទៀត\n"
    "/stats — ស្ថិតិក្រុមនេះ\n"
    "/settings — មើល ឬប្ដូរការកំណត់ (តែអ្នកគ្រប់គ្រង)\n\n"
    "<b>ការប្រើ /settings</b>\n"
    "<code>/settings</code> — មើលការកំណត់បច្ចុប្បន្ន\n"
    "<code>/settings maxsize &lt;MB&gt;</code> — កំណត់ទំហំឯកសារអតិបរមា\n"
    "<code>/settings blocklist on|off</code> — បើក/បិទការទប់ស្កាត់បន្ថែម\n"
    "<code>/settings addext &lt;.ext&gt;</code> — បន្ថែមប្រភេទហាម\n"
    "<code>/settings removeext &lt;.ext&gt;</code> — ដកប្រភេទហាម\n\n"
    "<code>.exe</code>, <code>.js</code>, <code>.rar</code>, <code>.zip</code> ត្រូវបានហាមជានិច្ចដោយមិនទាញយក។ "
    "ឯកសារផ្សេងទៀតស្កេនដោយ ClamAV។"
)

SCANNING = "🔍 កំពុងស្កេនឯកសារដោយ ClamAV..."

SCAN_REPLY_HINT = "សូមឆ្លើយតបទៅសារដែលមានឯកសារ ដោយប្រើ /scan ដើម្បីស្កេនម្ដងទៀត។"

NOT_ADMIN = "🚫 មានតែអ្នកគ្រប់គ្រងក្រុមទេ ទើបអាចប្ដូរការកំណត់សុវត្ថិភាពបាន។"

SETTINGS_USAGE = "ប្រើ /settings ដោយគ្មានអាគុយម៉ង់ ដើម្បីមើលរបៀបប្រើ។"
MAXSIZE_USAGE = "ប្រើ៖ /settings maxsize &lt;MB&gt;"

VERIFY_FAIL_SCANNER = (
    "⚠️ <b>មិនអាចផ្ទៀងផ្ទាត់ឯកសារនេះបានទេ។</b>\n"
    "ម៉ាស៊ីនស្កេនមិនអាចប្រើបាន ឬស្កេនបរាជ័យ។ "
    "ឯកសារនេះ<b>មិន</b>ត្រូវបានបញ្ជាក់ថាមានសុវត្ថិភាពទេ — សូមទាក់ទងអ្នកគ្រប់គ្រងមុនបើកវា។"
)

VERIFY_FAIL_NETWORK = (
    "⚠️ <b>មិនអាចផ្ទៀងផ្ទាត់ឯកសារនេះបានទេ។</b>\n"
    "Block/Telegram បានផ្អាកការស្កេន។ "
    "ឯកសារនេះ<b>មិន</b>ត្រូវបានបញ្ជាក់ថាមានសុវត្ថិភាពទេ។"
)


def blocked_file(
    name: str,
    size: str,
    reason: str,
    note: str,
    origin: str | None = None,
) -> str:
    reason_line = reason
    if origin:
        reason_line = (
            f"{reason}\n"
            f"⚠️ file Forwarded from: {esc(origin)}"
        )
    return (
        f"🚫 <b>បានទប់ស្កាត់ឯកសារ</b>\n"
        f"📄 ឈ្មោះ៖ <code>{esc(name)}</code>\n"
        f"📦 ទំហំ៖ {esc(size)}\n"
        f"⛔ មូលហេតុ៖ {reason_line}\n"
        f"❌ Bot បានលុបឯកសារ។{note}"
    )


def too_large(name: str, size: str, limit_mb: int, note: str) -> str:
    return (
        f"🚫 <b>ឯកសារធំពេក</b>\n"
        f"<code>{esc(name)}</code> មានទំហំ {esc(size)} "
        f"លើសពីដែនកំណត់ {limit_mb} MB។{note}"
    )


def allowed(name: str, size: str, ext: str, mime: str) -> str:
    return (
        f"✅ <b>អនុញ្ញាត</b>\n"
        f"📄 ឈ្មោះ៖ <code>{esc(name)}</code>\n"
        f"📦 ទំហំ៖ {esc(size)}\n"
        f"📎 ប្រភេទ៖ <code>{esc(ext)}</code> / <code>{esc(mime)}</code>\n"
        f"🛡 ClamAV៖ រកមិនឃើញមេរោគ"
    )


def infected(name: str, signature: str, note: str) -> str:
    return (
        f"🚨 <b>រកឃើញមេរោគ</b>\n"
        f"📄 ឈ្មោះ៖ <code>{esc(name)}</code>\n"
        f"🦠 ការរកឃើញ៖ <code>{esc(signature)}</code>\n"
        f"❌ Bot បានលុបឯកសារ។{note}"
    )


def status(
    uptime: str,
    clamav_ok: bool,
    max_mb: int,
    blocking_on: bool,
    blocked_exts: str,
    always_blocked: str,
) -> str:
    clamav = (
        "🟢 ClamAV៖ ភ្ជាប់បាន"
        if clamav_ok
        else "🔴 ClamAV៖ មិនអាចប្រើបាន — ឯកសារអនុញ្ញាតមិនអាចផ្ទៀងផ្ទាត់បានទេ"
    )
    blocking = "បើក" if blocking_on else "បិទ"
    return (
        f"<b>ស្ថានភាព Bot</b>\n"
        f"🟢 ពេលដំណើរការ៖ {esc(uptime)}\n"
        f"{clamav}\n"
        f"🟢 ទប់ស្កាត់ភ្លាម៖ .exe / .js / .src / .rar / .zip (មិនទាញយក)\n"
        f"🟢 ស្កេន ClamAV៖ ឯកសារអនុញ្ញាត (រូបថត, PDF, Word, …)\n"
        f"🟢 Forwarded៖ បង្ហាញតែពេលទប់ស្កាត់ (មូលហេតុ)\n\n"
        f"<b>ការកំណត់ក្រុម</b>\n"
        f"ទំហំអតិបរមា៖ {max_mb} MB\n"
        f"ការទប់ស្កាត់ប្រភេទ៖ {blocking}\n"
        f"ប្រភេទហាម៖ {esc(blocked_exts)}\n"
        f"ហាមជានិច្ច៖ {esc(always_blocked)}"
    )


def stats(total: int, safe: int, infected_n: int, errors: int, blocked: int, too_large_n: int) -> str:
    return (
        f"<b>ស្ថិតិស្កេនសម្រាប់ក្រុមនេះ</b>\n"
        f"ឯកសារសរុប៖ {total}\n"
        f"✅ អនុញ្ញាត (ClamAV ស្អាត)៖ {safe}\n"
        f"🚨 រកឃើញមេរោគ៖ {infected_n}\n"
        f"⚠️ ស្កេនបរាជ័យ៖ {errors}\n"
        f"🚫 ទប់ស្កាត់តាមប្រភេទ៖ {blocked}\n"
        f"📦 បដិសេធ (ធំពេក)៖ {too_large_n}"
    )


def current_settings(max_mb: int, blocking_on: bool, blocked_exts: str, always_blocked: str) -> str:
    blocking = "បើក" if blocking_on else "បិទ"
    return (
        f"<b>ការកំណត់បច្ចុប្បន្ន</b>\n"
        f"ទំហំអតិបរមា៖ {max_mb} MB\n"
        f"ការទប់ស្កាត់ប្រភេទ៖ {blocking}\n"
        f"ប្រភេទហាម៖ {esc(blocked_exts)}\n"
        f"ហាមជានិច្ច៖ {esc(always_blocked)}\n\n"
        f"អ្នកគ្រប់គ្រងអាចប្ដូរដោយ៖\n"
        f"<code>/settings maxsize &lt;MB&gt;</code>\n"
        f"<code>/settings blocklist on|off</code>\n"
        f"<code>/settings addext &lt;.ext&gt;</code>\n"
        f"<code>/settings removeext &lt;.ext&gt;</code>"
    )


def maxsize_range(hard_max: int) -> str:
    return f"តម្លៃត្រូវនៅចន្លោះ ១ ដល់ {hard_max} MB។"


def maxsize_set(mb: int) -> str:
    return f"✅ បានកំណត់ទំហំអតិបរមា {mb} MB។"


def blocklist_set(enabled: bool) -> str:
    state = "បើក" if enabled else "បិទ"
    return (
        f"✅ បាន{state}ការទប់ស្កាត់ប្រភេទបន្ថែម។ "
        f"កម្មវិធីដូច <code>.exe</code> នៅតែហាម។"
    )


def ext_added(ext: str) -> str:
    return f"✅ បានបន្ថែម <code>{esc(ext)}</code> ទៅបញ្ជីហាម។"


def ext_removed(ext: str) -> str:
    return f"✅ បានដក <code>{esc(ext)}</code> ចេញពីបញ្ជីហាម។"


def ext_always_blocked(ext: str) -> str:
    return f"🚫 <code>{esc(ext)}</code> ត្រូវបានហាមជានិច្ច មិនអាចដកបានទេ។"
