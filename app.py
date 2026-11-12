import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import httpx
from sqlalchemy import func, select, update as sqlalchemy_update
from telegram import InlineKeyboardButton, KeyboardButton, ReplyKeyboardMarkup, Update
from telegram import InlineKeyboardMarkup as _TgInlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from db import allocations, api_keys, api_permissions, api_usage, app_settings, balance_transactions, engine, init_db, now, otp_rates, provider_settings, rate_limits, user_provider_keys, users, withdrawals
from secrets_store import decrypt, encrypt

BOT_TOKEN = os.environ['BOT_TOKEN']
ADMIN_IDS = {int(x.strip()) for x in os.getenv('ADMIN_IDS', '').split(',') if x.strip().isdigit()}
PROVIDER_BASE = (os.getenv('TGZ_API_BASE') or os.getenv('PROVIDER_API_BASE', '')).rstrip('/')
MASTER_KEY = os.getenv('PROVIDER_API_KEY', '')
PUBLIC_API_BASE = os.getenv('PUBLIC_API_BASE', '').rstrip('/')
if not PROVIDER_BASE or not MASTER_KEY:
    raise RuntimeError('Set PROVIDER_API_BASE and PROVIDER_API_KEY')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Telegram coloured buttons (Bot API 9.4+: style = primary/blue, success/green,
# danger/red). Needs python-telegram-bot >= 22.7; older versions fall back to
# api_kwargs, and old Telegram clients simply show normal buttons.
# ---------------------------------------------------------------------------
BTN_PRIMARY, BTN_SUCCESS, BTN_DANGER = 'primary', 'success', 'danger'
_DANGER_RE = re.compile(r'\b(back|close|cancel|delete|reject|regen|regenerate|revoke|admin panel)\b', re.I)
_SUCCESS_RE = re.compile(r'\b(approve|paid|confirm|submit|yes)\b', re.I)


def _style_for(text, data, position, row_len):
    probe = f'{text} {data or ""}'.replace('_', ' ')
    if _DANGER_RE.search(probe):
        return BTN_DANGER
    if _SUCCESS_RE.search(probe):
        return BTN_SUCCESS
    if row_len == 1:
        return BTN_PRIMARY
    return BTN_SUCCESS if position == 0 else BTN_PRIMARY


def _make_inline_button(text, style=None, **kwargs):
    if not style:
        return InlineKeyboardButton(text, **kwargs)
    try:
        return InlineKeyboardButton(text, style=style, **kwargs)
    except TypeError:
        return InlineKeyboardButton(text, api_kwargs={'style': style}, **kwargs)


def InlineKeyboardMarkup(rows, *args, **kwargs):
    """Drop-in replacement: colours every inline button (left green, right blue, back/close red)."""
    styled_rows = []
    for row in rows:
        row = list(row)
        new_row = []
        for position, button in enumerate(row):
            if not isinstance(button, InlineKeyboardButton) or getattr(button, 'style', None):
                new_row.append(button); continue
            extra = {}
            if button.callback_data is not None:
                extra['callback_data'] = button.callback_data
            if button.url:
                extra['url'] = button.url
            if not extra:
                new_row.append(button); continue
            new_row.append(_make_inline_button(button.text, _style_for(button.text, button.callback_data, position, len(row)), **extra))
        styled_rows.append(new_row)
    return _TgInlineKeyboardMarkup(styled_rows, *args, **kwargs)


def _reply_button(text, style):
    try:
        return KeyboardButton(text, style=style)
    except TypeError:
        return KeyboardButton(text, api_kwargs={'style': style})


ISSUED_KEYS = {}
PENDING_TGZ_SETTINGS = {}
PENDING_WITHDRAWALS = {}
PENDING_ADMIN_REJECTIONS = {}
LEADERBOARD_TASKS = {}
LEADERBOARD_STATE = {}
HEALTH_SERVER = None


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in {'/', '/health', '/healthz'}:
            self.send_response(404)
            self.end_headers()
            return
        body = b'OK'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        logger.info('Health server: ' + format, *args)


def start_health_server():
    """Open Render's HTTP port while the Telegram polling loop runs."""
    global HEALTH_SERVER
    port = int(os.getenv('PORT', '10000'))
    HEALTH_SERVER = ThreadingHTTPServer(('0.0.0.0', port), HealthHandler)
    Thread(target=HEALTH_SERVER.serve_forever, name='health-server', daemon=True).start()
    logger.info('Health server listening on 0.0.0.0:%s', port)

def hashkey(key): return hashlib.sha256(key.encode()).hexdigest()
def issue_key(): return 'tgz_' + secrets.token_urlsafe(32)


DEFAULT_OTP_RATE_PAISA = 40
TGZ_SETTING_KEYS = {
    'withdraw': 'withdraw_enabled', 'min_withdraw': 'min_withdraw_paisa', 'otp_reward': 'otp_reward_paisa',
    'refer_reward': 'refer_reward_paisa', 'cooldown': 'cooldown_seconds', 'num_req': 'num_per_request',
    'num_share': 'num_per_share', 'support': 'support_link_enabled', 'w_methods': 'withdraw_methods',
    'w_group': 'withdraw_group_enabled', 'api_url': 'api_url',
}


def bdt_to_paisa(value):
    """Convert a positive BDT amount to integer paisa without float rounding errors."""
    amount = Decimal(str(value)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    if amount < 0:
        raise ValueError('Amount cannot be negative.')
    return int(amount * 100)


def paisa_to_bdt(value):
    return f'{Decimal(int(value or 0)) / Decimal(100):.2f}'


def get_tgz_setting(name, default=''):
    with engine.begin() as c:
        row = c.execute(select(app_settings.c.value).where(app_settings.c.name == name)).first()
    return row[0] if row else default


def get_tgz_settings():
    """Load all TGZ settings with one database round trip."""
    with engine.begin() as c:
        rows = c.execute(select(app_settings.c.name, app_settings.c.value)).mappings().all()
    return {row['name']: row['value'] for row in rows}


def set_tgz_setting(name, value, updated_by):
    with engine.begin() as c:
        values = {'value': str(value), 'updated_by': updated_by, 'updated_at': now()}
        if c.execute(select(app_settings.c.name).where(app_settings.c.name == name)).first():
            c.execute(sqlalchemy_update(app_settings).where(app_settings.c.name == name).values(**values))
        else:
            c.execute(app_settings.insert().values(name=name, **values))


def tgz_control_keyboard():
    settings = get_tgz_settings()

    def setting(name, default):
        return settings.get(name, default)

    def on_off(value):
        return 'ON' if str(value).lower() in {'on', 'true', '1'} else 'OFF'

    withdraw = on_off(setting('withdraw_enabled', 'on'))
    support = on_off(setting('support_link_enabled', 'on'))
    w_group = on_off(setting('withdraw_group_enabled', 'on'))
    min_withdraw = paisa_to_bdt(setting('min_withdraw_paisa', '5000'))
    otp_reward = paisa_to_bdt(setting('otp_reward_paisa', '40'))
    refer_reward = paisa_to_bdt(setting('refer_reward_paisa', '20'))
    cooldown = setting('cooldown_seconds', '10')
    num_req = setting('num_per_request', '3')
    num_share = setting('num_per_share', '1')
    api_url = setting('api_url', 'AUTO')
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f'WITHDRAW: {withdraw}', callback_data='tgz_toggle_withdraw')],
        [InlineKeyboardButton(f'MIN WITHDRAW: {min_withdraw}', callback_data='tgz_edit_min_withdraw'), InlineKeyboardButton(f'OTP REWARD: {otp_reward}', callback_data='tgz_edit_otp_reward')],
        [InlineKeyboardButton(f'REFER REWARD: {refer_reward}', callback_data='tgz_edit_refer_reward'), InlineKeyboardButton(f'COOLDOWN: {cooldown}s', callback_data='tgz_edit_cooldown')],
        [InlineKeyboardButton(f'NUM/REQ: {num_req}', callback_data='tgz_edit_num_req'), InlineKeyboardButton(f'NUM/SHARE: {num_share}', callback_data='tgz_edit_num_share')],
        [InlineKeyboardButton(f'SUPPORT LINK: {support}', callback_data='tgz_toggle_support'), InlineKeyboardButton('W. METHODS', callback_data='tgz_edit_w_methods')],
        [InlineKeyboardButton(f'W. GROUP: {w_group}', callback_data='tgz_toggle_w_group'), InlineKeyboardButton(f'API URL: {api_url}', callback_data='tgz_edit_api_url')],
        [InlineKeyboardButton('BACK', callback_data='settings_back')],
    ])


def tgz_control_text():
    def on_off(value): return 'ON' if str(value).lower() in {'on', 'true', '1'} else 'OFF'
    api_url = get_tgz_setting('api_url', 'AUTO')
    if api_url.upper() == 'AUTO':
        api_url = PUBLIC_API_BASE or 'AUTO'
    return (
        '🕹 TGZ CONTROL PANEL\n'
        f"WITHDRAW: {on_off(get_tgz_setting('withdraw_enabled', 'on'))}\n"
        f"MIN WITHDRAW: {paisa_to_bdt(get_tgz_setting('min_withdraw_paisa', '5000'))} টাকা\n"
        f"OTP REWARD: {paisa_to_bdt(get_tgz_setting('otp_reward_paisa', '40'))}\n"
        f"REFER REWARD: {paisa_to_bdt(get_tgz_setting('refer_reward_paisa', '20'))}\n"
        f"COOLDOWN: {get_tgz_setting('cooldown_seconds', '10')}s\n"
        f"NUM/REQ: {get_tgz_setting('num_per_request', '3')}\n"
        f"NUM/SHARE: {get_tgz_setting('num_per_share', '1')}\n"
        f"SUPPORT LINK: {on_off(get_tgz_setting('support_link_enabled', 'on'))}\n"
        f"W. METHODS: {get_tgz_setting('withdraw_methods', 'bKash,Nagad')}\n"
        f"W. GROUP: {on_off(get_tgz_setting('withdraw_group_enabled', 'on'))}\n"
        f"API URL: {api_url}\n\n"
        'Use the buttons below to change any setting.'
    )


def tgz_control_panel_message():
    return '🕹 TGZ CONTROL PANEL'


def apply_tgz_value(key, raw_value, uid):
    """Validate and save a value submitted from the interactive control panel."""
    setting_name = TGZ_SETTING_KEYS[key]
    raw_value = str(raw_value).strip()
    if key in {'withdraw', 'support', 'w_group'}:
        value = raw_value.lower()
        if value not in {'on', 'off'}:
            raise ValueError('Use ON or OFF.')
    elif key in {'min_withdraw', 'otp_reward', 'refer_reward'}:
        paisa = bdt_to_paisa(raw_value)
        if paisa <= 0:
            raise ValueError('Amount must be positive.')
        value = str(paisa)
    elif key in {'cooldown', 'num_req', 'num_share'}:
        value = str(int(raw_value))
        if int(value) < 0 or (key != 'cooldown' and int(value) < 1):
            raise ValueError('Invalid number.')
    elif key == 'api_url':
        value = raw_value if raw_value.upper() == 'AUTO' else raw_value.rstrip('/')
        if value.upper() != 'AUTO' and not re.match(r'^https?://', value):
            raise ValueError('API URL must start with http:// or https://, or be AUTO.')
        value = value.upper() if value == 'AUTO' else value
    elif key == 'w_methods':
        value = raw_value
        if not value:
            raise ValueError('Enter at least one withdrawal method.')
    else:
        value = raw_value
    set_tgz_setting(setting_name, value, uid)
    if key == 'otp_reward':
        with engine.begin() as c:
            c.execute(sqlalchemy_update(otp_rates).where(otp_rates.c.service == '__default__').values(rate_paisa=int(value), updated_by=uid, updated_at=now()))
    return value


def otp_rate_for(service):
    """Return the service-specific OTP rate, falling back to the default rate."""
    service_name = str(service or '').strip() or '__default__'
    with engine.begin() as c:
        row = None if service_name == '__default__' else c.execute(select(otp_rates).where(otp_rates.c.service == service_name, otp_rates.c.enabled == True)).mappings().first()
    return int(row['rate_paisa']) if row else int(get_tgz_setting('otp_reward_paisa', str(DEFAULT_OTP_RATE_PAISA)))


def credit_otp_balance(uid, allocation_id, service):
    """Credit one successful OTP exactly once and return the credited paisa."""
    rate_paisa = otp_rate_for(service)
    with engine.begin() as c:
        c.execute(select(allocations.c.id).where(allocations.c.id == allocation_id).with_for_update()).first()
        existing = c.execute(select(balance_transactions.c.id).where(
            balance_transactions.c.transaction_type == 'otp_credit',
            balance_transactions.c.allocation_id == allocation_id,
        )).first()
        if existing:
            return 0
        c.execute(balance_transactions.insert().values(
            tg_id=uid, amount_paisa=rate_paisa, transaction_type='otp_credit',
            allocation_id=allocation_id, description=f'OTP credit ({service or "unknown service"})', created_at=now(),
        ))
        c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(
            balance_paisa=users.c.balance_paisa + rate_paisa,
        ))
        c.execute(sqlalchemy_update(allocations).where(allocations.c.id == allocation_id).values(
            credit_amount_paisa=rate_paisa, credited_at=now(),
        ))
    return rate_paisa


def _normalise_number(value):
    """Return only digits so provider numbers can be compared safely."""
    return re.sub(r'\D+', '', str(value or ''))


def extract_otp(response_data, number=None):
    """Extract an OTP from legacy and current provider response formats.

    Supported formats include:
    - {"data": {"otp": "123456", "service": "FACEBOOK"}}
    - {"data": {"otps": [{"message": "Your code is 123456", "sid": "FACEBOOK"}]}}
    - {"data": [{"otp": "123456"}]}   (list directly under data)
    Returns {'otp': str, 'service': ...} or None.
    """
    if not isinstance(response_data, dict):
        return None
    data = response_data.get('data')
    if isinstance(data, list):
        data = {'otps': data}
    if not isinstance(data, dict):
        return None

    candidates = []
    if isinstance(data.get('otps'), list):
        candidates.extend(item for item in data['otps'] if isinstance(item, dict))
    if data.get('otp') is not None:
        candidates.insert(0, data)

    requested_number = _normalise_number(number)
    if requested_number and len(candidates) > 1:
        matching = [item for item in candidates if _normalise_number(item.get('number')) == requested_number]
        if matching:
            candidates = matching

    for item in candidates:
        otp = item.get('otp') or item.get('code')
        message = str(item.get('message') or '')
        if not otp and message:
            match = re.search(r'(?<!\d)(\d{6})(?!\d)', message)
            if not match:
                match = re.search(r'(?<!\d)(\d{4,8})(?!\d)', message)
            if match:
                otp = match.group(1)
        if otp is not None and str(otp).strip():
            return {
                'otp': str(otp).strip(),
                'service': item.get('service') or item.get('sid'),
                'otp_id': item.get('otp_id'),
                'time': item.get('time'),
            }
    return None

def ensure_user(uid, username=None, display_name=None):
    with engine.begin() as c:
        if not c.execute(select(users.c.tg_id).where(users.c.tg_id == uid)).first():
            c.execute(users.insert().values(tg_id=uid, username=username, display_name=display_name, enabled=True, banned=False, balance_paisa=0, created_at=now()))
        elif username is not None or display_name is not None:
            c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(username=username, display_name=display_name))

def user_row(uid):
    with engine.begin() as c: return c.execute(select(users).where(users.c.tg_id == uid)).mappings().first()

def provider_key_for(uid):
    with engine.begin() as c:
        own = c.execute(select(user_provider_keys).where(user_provider_keys.c.tg_id == uid, user_provider_keys.c.enabled == True)).mappings().first()
        if own: return decrypt(own['key_encrypted'])
        admin = c.execute(select(provider_settings).where(provider_settings.c.name == 'provider_api_key')).mappings().first()
    return decrypt(admin['value_encrypted']) if admin else MASTER_KEY

def generate_key(uid, label='telegram'):
    ensure_user(uid); key = issue_key()
    with engine.begin() as c:
        c.execute(api_keys.insert().values(tg_id=uid, key_hash=hashkey(key), key_prefix=key[:12], label=label, enabled=True, created_at=now()))
        c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(api_hash=hashkey(key), api_prefix=key[:12], enabled=True))
    ISSUED_KEYS[uid] = key
    return key


def ensure_document_key(uid, label='tgz-api-document', force=False):
    """Return a full API key, rotating an unrecoverable hash-only key after restart."""
    if force:
        revoke_all_keys(uid)
    if uid in ISSUED_KEYS:
        return ISSUED_KEYS[uid]
    existing = user_row(uid)
    if existing and existing['api_hash']:
        # Only the hash is stored, so the original secret cannot be recovered.
        # Revoke it before issuing a replacement that can actually be shown.
        revoke_all_keys(uid)
    return generate_key(uid, label=label)

def revoke_all_keys(uid):
    ISSUED_KEYS.pop(uid, None)  # a revoked key must never be shown/reused again (Regenerate Key bug)
    with engine.begin() as c:
        c.execute(sqlalchemy_update(api_keys).where(api_keys.c.tg_id == uid, api_keys.c.revoked_at.is_(None)).values(enabled=False, revoked_at=now()))
        c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(api_hash=None, api_prefix=None))

def kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('API KEY', callback_data='key'), InlineKeyboardButton('COPY API KEY', callback_data='copy')],
        [InlineKeyboardButton('API DOCUMENT', callback_data='docs'), InlineKeyboardButton('TEST API', callback_data='test')],
        [InlineKeyboardButton('REGENERATE KEY', callback_data='regen'), InlineKeyboardButton('MY STATUS', callback_data='status')],
        [InlineKeyboardButton('MY USAGE', callback_data='usage'), InlineKeyboardButton('MY ALLOCATIONS', callback_data='allocations')],
    ])

def user_keyboard(uid):
    rows = [
        [_reply_button('GET NUMBER', BTN_PRIMARY), _reply_button('2FA ONLINE', BTN_PRIMARY)],
        [_reply_button('Refer', BTN_SUCCESS), _reply_button('WITHDRAWAL', BTN_DANGER)],
        [_reply_button('Leader Board', BTN_SUCCESS), _reply_button('SUPPORT', BTN_PRIMARY)],
        [_reply_button('API DOCUMENT', BTN_PRIMARY)],
        [_reply_button('BALANCE', BTN_SUCCESS)],
    ]
    if uid in ADMIN_IDS:
        rows.append([_reply_button('STATUS', BTN_SUCCESS), _reply_button('Admin Panel', BTN_DANGER)])
    else:
        rows.append([_reply_button('STATUS', BTN_SUCCESS)])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)


def leaderboard_keyboard(mode='all'):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('🏆 ALL-TIME' + (' ✓' if mode == 'all' else ''), callback_data='lb_all'), InlineKeyboardButton('📅 WEEKLY' + (' ✓' if mode == 'weekly' else ''), callback_data='lb_weekly')],
        [InlineKeyboardButton('🔄 REFRESH', callback_data='lb_refresh'), InlineKeyboardButton('👤 MY RANK', callback_data='lb_my_rank')],
        [InlineKeyboardButton('🔙 BACK', callback_data='lb_back')],
    ])


def leaderboard_aggregate(mode='all'):
    """Aggregate only unique positive OTP-credit ledger entries for successful allocations."""
    source = users.join(balance_transactions, users.c.tg_id == balance_transactions.c.tg_id).join(
        allocations, allocations.c.id == balance_transactions.c.allocation_id,
    )
    conditions = [
        balance_transactions.c.transaction_type == 'otp_credit',
        balance_transactions.c.amount_paisa > 0,
        allocations.c.status == 'success',
        balance_transactions.c.created_at <= now(),
    ]
    if mode == 'weekly':
        conditions.append(balance_transactions.c.created_at >= now() - timedelta(days=7))
    return select(
        users.c.tg_id,
        users.c.username,
        users.c.display_name,
        func.count(balance_transactions.c.id).label('otp_count'),
        func.coalesce(func.sum(balance_transactions.c.amount_paisa), 0).label('earnings_paisa'),
    ).select_from(source).where(*conditions).group_by(
        users.c.tg_id, users.c.username, users.c.display_name,
    )


def leaderboard_rows(mode='all', limit=10):
    query = leaderboard_aggregate(mode).order_by(
        func.sum(balance_transactions.c.amount_paisa).desc(),
        func.count(balance_transactions.c.id).desc(),
        users.c.tg_id.asc(),
    ).limit(limit)
    with engine.begin() as c:
        return c.execute(query).mappings().all()


def leaderboard_personal(uid, mode='all'):
    aggregate = leaderboard_aggregate(mode).subquery('leaderboard_aggregate')
    rank_order = [aggregate.c.earnings_paisa.desc(), aggregate.c.otp_count.desc(), aggregate.c.tg_id.asc()]
    ranked = select(
        aggregate,
        func.row_number().over(order_by=rank_order).label('rank'),
    ).subquery('ranked_leaderboard')
    with engine.begin() as c:
        return c.execute(select(ranked).where(ranked.c.tg_id == uid)).mappings().first()


def leaderboard_name(row):
    if row.get('username'):
        return '@' + row['username'].lstrip('@')
    if row.get('display_name'):
        return row['display_name']
    return f"User {row['tg_id']}"


def leaderboard_text(uid, mode='all'):
    title = 'ALL-TIME LEADER BOARD' if mode == 'all' else 'WEEKLY LEADER BOARD (LAST 7 DAYS)'
    rows = leaderboard_rows(mode)
    bd_timezone = timezone(timedelta(hours=6))
    updated_at = datetime.now(bd_timezone).strftime('%I:%M:%S %p')
    lines = [f'🏆 {title}', '🔄 Refreshes every 5 sec', f'Updated {updated_at}', '━━━━━━━━━━━━']
    if rows:
        for rank, row in enumerate(rows, 1):
            lines.append(f"{rank}. {leaderboard_name(row)}\n   OTPs: {row['otp_count']} · Earnings: {paisa_to_bdt(row['earnings_paisa'])} BDT")
    else:
        lines.append('No successful OTP earnings yet.')
    personal = leaderboard_personal(uid, mode)
    lines.append('\n👤 YOUR RANK')
    if personal:
        lines.append(f"Rank: #{personal['rank']}\nSuccessful OTPs: {personal['otp_count']}\nEarnings: {paisa_to_bdt(personal['earnings_paisa'])} BDT")
    else:
        lines.append('No successful OTP earnings recorded for you yet.')
    return '\n'.join(lines)


def cancel_leaderboard(uid):
    task = LEADERBOARD_TASKS.pop(uid, None)
    if task and not task.done():
        task.cancel()
    LEADERBOARD_STATE.pop(uid, None)


async def auto_refresh_leaderboard(bot, uid):
    try:
        while True:
            await asyncio.sleep(5)
            state = LEADERBOARD_STATE.get(uid)
            if not state:
                return
            text = leaderboard_text(uid, state['mode'])
            try:
                await bot.edit_message_text(
                    chat_id=state['chat_id'], message_id=state['message_id'],
                    text=text, reply_markup=leaderboard_keyboard(state['mode']),
                )
            except Exception as exc:
                if 'not modified' not in str(exc).lower():
                    raise
    except asyncio.CancelledError:
        return
    except Exception:
        logger.exception('Leaderboard auto-refresh stopped for user %s', uid)


async def show_leaderboard(message, uid, mode='all', edit=False, bot=None):
    cancel_leaderboard(uid)
    text = leaderboard_text(uid, mode)
    if edit:
        sent = await message.edit_text(text, reply_markup=leaderboard_keyboard(mode))
    else:
        sent = await message.reply_text(text, reply_markup=leaderboard_keyboard(mode))
    LEADERBOARD_STATE[uid] = {'chat_id': sent.chat_id, 'message_id': sent.message_id, 'mode': mode}
    LEADERBOARD_TASKS[uid] = asyncio.create_task(auto_refresh_leaderboard(bot or message.get_bot(), uid))


def withdrawal_methods():
    raw = get_tgz_setting('withdraw_methods', 'bKash,Nagad')
    return list(dict.fromkeys(x.strip() for x in raw.split(',') if x.strip()))


def mask_payment_info(value):
    value = str(value or '')
    if len(value) <= 4:
        return '****'
    return '*' * max(0, len(value) - 4) + value[-4:]


def withdrawal_main_text(uid):
    row = user_row(uid)
    enabled = get_tgz_setting('withdraw_enabled', 'on').lower() in {'on', 'true', '1'}
    minimum = get_tgz_setting('min_withdraw_paisa', '5000')
    methods = ', '.join(withdrawal_methods()) or 'Not configured'
    return (f'💸 WITHDRAWAL SYSTEM\n\n'
            f"STATUS: {'ON' if enabled else 'OFF'}\n"
            f'YOUR BALANCE: {paisa_to_bdt(row["balance_paisa"] if row else 0)} BDT\n'
            f'MINIMUM: {paisa_to_bdt(minimum)} BDT\n'
            f'METHODS: {methods}')


def withdrawal_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('💸 WITHDRAW', callback_data='wd_open')],
        [InlineKeyboardButton('📜 WITHDRAWAL HISTORY', callback_data='wd_history')],
        [InlineKeyboardButton('🔙 BACK', callback_data='wd_back')],
    ])


def withdrawal_method_keyboard():
    methods = withdrawal_methods()
    rows = [[InlineKeyboardButton(method, callback_data=f'wd_method_{index}')] for index, method in enumerate(methods)]
    rows.append([InlineKeyboardButton('🔙 BACK', callback_data='wd_back')])
    return InlineKeyboardMarkup(rows)


def withdrawal_confirm_keyboard():
    return InlineKeyboardMarkup([[
        InlineKeyboardButton('✅ CONFIRM', callback_data='wd_confirm'),
        InlineKeyboardButton('❌ CANCEL', callback_data='wd_cancel'),
    ]])


def withdrawal_id():
    return 'WD-' + secrets.token_hex(6).upper()


def reserve_withdrawal(uid, username, amount_paisa, method, payment_info):
    """Create one pending withdrawal and reserve balance atomically."""
    encrypted = encrypt(payment_info)
    with engine.begin() as c:
        updated = c.execute(sqlalchemy_update(users).where(
            users.c.tg_id == uid, users.c.balance_paisa >= amount_paisa,
        ).values(balance_paisa=users.c.balance_paisa - amount_paisa))
        if updated.rowcount != 1:
            raise ValueError('Insufficient balance or user was changed concurrently.')
        wid = withdrawal_id()
        c.execute(withdrawals.insert().values(
            withdrawal_id=wid, tg_id=uid, username=username or '', amount_paisa=amount_paisa,
            method=method, payment_info_encrypted=encrypted, status='pending', requested_at=now(),
        ))
        c.execute(balance_transactions.insert().values(
            tg_id=uid, amount_paisa=-amount_paisa, transaction_type='withdrawal_debit',
            withdrawal_id=wid, description=f'Withdrawal reserve {wid}', created_at=now(),
        ))
    return wid


def withdrawal_history(uid):
    with engine.begin() as c:
        return c.execute(select(withdrawals).where(withdrawals.c.tg_id == uid).order_by(withdrawals.c.id.desc()).limit(20)).mappings().all()


def admin_withdrawals(status=None):
    with engine.begin() as c:
        query = select(withdrawals).order_by(withdrawals.c.id.desc()).limit(50)
        if status:
            query = query.where(withdrawals.c.status == status)
        return c.execute(query).mappings().all()


def get_withdrawal(wid):
    with engine.begin() as c:
        return c.execute(select(withdrawals).where(withdrawals.c.withdrawal_id == wid)).mappings().first()


def approve_withdrawal(wid, admin_id):
    with engine.begin() as c:
        row = c.execute(select(withdrawals).where(withdrawals.c.withdrawal_id == wid).with_for_update()).mappings().first()
        if not row or row['status'] != 'pending':
            return False, row['status'] if row else 'missing'
        c.execute(sqlalchemy_update(withdrawals).where(withdrawals.c.withdrawal_id == wid, withdrawals.c.status == 'pending').values(status='approved', approved_at=now(), approved_by=admin_id))
    return True, 'approved'


def reject_withdrawal(wid, admin_id, reason):
    with engine.begin() as c:
        row = c.execute(select(withdrawals).where(withdrawals.c.withdrawal_id == wid).with_for_update()).mappings().first()
        if not row or row['status'] != 'pending':
            return False, row['status'] if row else 'missing'
        c.execute(sqlalchemy_update(users).where(users.c.tg_id == row['tg_id']).values(balance_paisa=users.c.balance_paisa + row['amount_paisa']))
        c.execute(balance_transactions.insert().values(
            tg_id=row['tg_id'], amount_paisa=row['amount_paisa'], transaction_type='withdrawal_refund',
            withdrawal_id=wid, description=f'Withdrawal refund {wid}', created_at=now(),
        ))
        c.execute(sqlalchemy_update(withdrawals).where(withdrawals.c.withdrawal_id == wid, withdrawals.c.status == 'pending').values(status='rejected', rejection_reason=reason, rejected_at=now(), rejected_by=admin_id))
    return True, 'rejected'


def mark_withdrawal_paid(wid, admin_id):
    with engine.begin() as c:
        row = c.execute(select(withdrawals).where(withdrawals.c.withdrawal_id == wid).with_for_update()).mappings().first()
        if not row or row['status'] != 'approved':
            return False, row['status'] if row else 'missing'
        c.execute(sqlalchemy_update(withdrawals).where(withdrawals.c.withdrawal_id == wid, withdrawals.c.status == 'approved').values(status='paid', paid_at=now(), paid_by=admin_id))
    return True, 'paid'


def withdrawal_status_label(status):
    return {'pending': 'Pending', 'approved': 'Approved', 'rejected': 'Rejected', 'paid': 'Paid'}.get(status, status.title())


def withdrawal_admin_keyboard(rows):
    buttons = []
    for row in rows:
        buttons.append([InlineKeyboardButton(f"{row['withdrawal_id']} · {paisa_to_bdt(row['amount_paisa'])} · {row['status'].upper()}", callback_data=f"wd_admin_view_{row['withdrawal_id']}")])
    buttons.append([InlineKeyboardButton('🔄 REFRESH', callback_data='wd_admin_list'), InlineKeyboardButton('🔙 BACK', callback_data='settings_back')])
    return InlineKeyboardMarkup(buttons)

def admin_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('Upload Number', callback_data='admin_upload'), InlineKeyboardButton('Delete files', callback_data='admin_delete')],
        [InlineKeyboardButton('Backup', callback_data='admin_backup'), InlineKeyboardButton('API Users', callback_data='admin_users')],
        [InlineKeyboardButton('Broadcast', callback_data='admin_broadcast'), InlineKeyboardButton('System', callback_data='admin_system')],
        [InlineKeyboardButton('Used number', callback_data='admin_used'), InlineKeyboardButton('Unused number', callback_data='admin_unused')],
        [InlineKeyboardButton('💸 Withdrawals', callback_data='wd_admin_list')],
        [InlineKeyboardButton('OTP Rate', callback_data='admin_otprate')],
        [InlineKeyboardButton('Add Bot', callback_data='admin_addbot'), InlineKeyboardButton('Close', callback_data='admin_close')],
    ])

def system_settings_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('StexSMS Control', callback_data='settings_stex'), InlineKeyboardButton('Force Join System', callback_data='settings_join')],
        [InlineKeyboardButton('Admin Management', callback_data='settings_admins'), InlineKeyboardButton('OTP Group', callback_data='settings_otpgroup')],
        [InlineKeyboardButton('User Management', callback_data='settings_users'), InlineKeyboardButton('TGZ Control', callback_data='settings_tgz')],
        [InlineKeyboardButton('Premium Emoji', callback_data='settings_emoji'), InlineKeyboardButton('Menu Design', callback_data='settings_menu')],
        [InlineKeyboardButton('Test', callback_data='settings_test'), InlineKeyboardButton('Back', callback_data='settings_back')],
    ])

def api_document_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton('Test API', callback_data='doc_test'), InlineKeyboardButton('Regenerate Key', callback_data='doc_regen')],
        [InlineKeyboardButton('Close', callback_data='doc_close')],
    ])

async def send_api_document(message, uid, force=False, username=None):
    key_line = ensure_document_key(uid, force=force)
    r = user_row(uid); configured_api_url = get_tgz_setting('api_url', 'AUTO'); base = (PUBLIC_API_BASE if configured_api_url.upper() == 'AUTO' else configured_api_url) or 'https://YOUR-API-SERVICE.onrender.com'; handle = '@' + username if username else str(uid)
    text = (f'━━━━━━━━━━━━━━━━━━\n'
            f'《🔑 API DOCUMENT 》\n'
            f'━━━━━━━━━━━━━━━━━━\n'
            f'✅ API ENABLED · {handle}\n'
            f'🔑 YOUR API KEY (save it now):\n{key_line}\n'
            f'🔐 The full key is not stored and cannot be recovered after a worker restart.\n'
            f'━━━━━━━━━━━━━━━━━━\n'
            f'🌐 BASE URL:\n{base}/api/v1\n\n'
            f'📌 Header: mauthapi: YOUR_KEY\n'
            f'➤ POST /getnum {{"rid":"26134"}}\n'
            f'➤ GET /otp?number=...&wait=25\n'
            f'➤ GET /success-otp\n'
            f'➤ GET /liveaccess · /console\n'
            f'━━━━━━━━━━━━━━━━━━\n'
            f'⚡ Number and OTP will be delivered through this bot; provider balance follows the selected TGZ key.')
    await message.reply_text(text, reply_markup=api_document_keyboard())


async def notify_withdrawal_admins(bot, row, event='New Withdrawal Request'):
    payment = decrypt(row['payment_info_encrypted'])
    text = (f'💸 {event}\n\nID: {row["withdrawal_id"]}\n'
            f'User ID: {row["tg_id"]}\nUsername: @{row["username"] or "-"}\n'
            f'Amount: {paisa_to_bdt(row["amount_paisa"])} BDT\nMethod: {row["method"]}\n'
            f'Payment: {payment}\nStatus: {withdrawal_status_label(row["status"])}')
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(admin_id, text, reply_markup=withdrawal_admin_action_keyboard(row))
        except Exception:
            logger.exception('Could not notify admin %s about withdrawal %s', admin_id, row['withdrawal_id'])


def withdrawal_admin_action_keyboard(row):
    buttons = []
    if row['status'] == 'pending':
        buttons.append([
            InlineKeyboardButton('✅ APPROVE', callback_data=f"wd_admin_approve_{row['withdrawal_id']}"),
            InlineKeyboardButton('❌ REJECT', callback_data=f"wd_admin_reject_{row['withdrawal_id']}"),
        ])
    elif row['status'] == 'approved':
        buttons.append([InlineKeyboardButton('💰 MARK AS PAID', callback_data=f"wd_admin_paid_{row['withdrawal_id']}")])
    buttons.append([InlineKeyboardButton('📜 ALL WITHDRAWALS', callback_data='wd_admin_list')])
    return InlineKeyboardMarkup(buttons)


def withdrawal_history_text(rows):
    if not rows:
        return '📜 WITHDRAWAL HISTORY\n\nNo withdrawal requests found.'
    parts = ['📜 WITHDRAWAL HISTORY']
    for row in rows:
        item = (f"\n\nID: {row['withdrawal_id']}\nAmount: {paisa_to_bdt(row['amount_paisa'])} BDT\n"
                f"Method: {row['method']}\nPayment: {mask_payment_info(decrypt(row['payment_info_encrypted']))}\n"
                f"Status: {withdrawal_status_label(row['status'])}\nRequested: {row['requested_at']}")
        if row['paid_at']:
            item += f"\nCompleted: {row['paid_at']}"
        if row['rejection_reason']:
            item += f"\nReason: {row['rejection_reason']}"
        parts.append(item)
    return ''.join(parts)


def withdrawal_admin_list_text(rows):
    if not rows:
        return '💸 WITHDRAWAL MANAGEMENT\n\nNo withdrawal requests found.'
    counts = {status: sum(1 for row in rows if row['status'] == status) for status in ('pending', 'approved', 'rejected', 'paid')}
    return (f"💸 WITHDRAWAL MANAGEMENT\n\nPending: {counts['pending']} | Approved: {counts['approved']}\n"
            f"Rejected: {counts['rejected']} | Paid: {counts['paid']}\n\nSelect a request to view details.")

async def dashboard_text(uid):
    with engine.begin() as c:
        files = c.execute(select(func.count()).select_from(allocations)).scalar_one()
        assigned = c.execute(select(func.count()).select_from(allocations).where(allocations.c.status.in_(['allocated', 'success']))).scalar_one()
        available = 0
        users_count = c.execute(select(func.count()).select_from(users)).scalar_one()
    return (f'📁 Files  » {files}\n🔢 Numbers  » {files}\n✅ Assigned  » {assigned}\n🚀 Available  » {available}\n\n'
            f'📊 STOCK LEVEL\n━━━━━━━━━━━━\n{available} free\n\n'
            f'API Users  » {users_count}')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id; ensure_user(uid, update.effective_user.username, update.effective_user.full_name)
    welcome = ('╔═══════════╗\n'
               ' 📊 MS NUMBER BOT\n'
               '╚═══════════╝\n'
               '🚀 Welcome to Number & OTP Service\n'
               '━━━━━━━━━━━━\n'
               '✅ Choose an option below\n'
               'to continue using the bot.\n'
               '💎 Premium OTP Service')
    await update.message.reply_text(welcome, reply_markup=user_keyboard(uid))

def provider_key_source(uid):
    with engine.begin() as c:
        own = c.execute(select(user_provider_keys.c.tg_id).where(user_provider_keys.c.tg_id == uid, user_provider_keys.c.enabled == True)).first()
        admin = c.execute(select(provider_settings.c.name).where(provider_settings.c.name == 'provider_api_key')).first()
    if own: return 'your own TGZ key (/settgzkey)'
    if admin: return 'admin key (/setproviderkey)'
    return 'environment PROVIDER_API_KEY'


def provider_base_is_own_api():
    """True when TGZ_API_BASE points at this project's own API service (same host as PUBLIC_API_BASE)."""
    try:
        a = (urlparse(PROVIDER_BASE).hostname or '').lower(); b = (urlparse(PUBLIC_API_BASE).hostname or '').lower()
    except Exception:
        return False
    return bool(a and b and a == b)


OWN_API_HINT = ('SETUP PROBLEM: TGZ_API_BASE points to this project\'s own API, which accepts only tgz_ keys issued by the bot '
                '(a real TGZ key is rejected as "Invalid API key").\n'
                'Fix A (direct, recommended): set TGZ_API_BASE = the real TGZ provider URL ending in /api/v1 and PROVIDER_API_KEY = your real TGZ key.\n'
                'Fix B (via own API): PROVIDER_API_KEY must be an ACTIVE tgz_ key from API DOCUMENT (Regenerate Key revokes the old one), '
                'and the API service needs PROVIDER_API_BASE + the real TGZ key.')


def _first_value(item, keys):
    for k in keys:
        v = item.get(k)
        if v not in (None, ''):
            return v
    return None


_RID_KEYS = ('rid', 'range_id', 'rangeId', 'range', 'range_rid', 'range_code', 'rangeCode')
_NAME_KEYS = ('name', 'title', 'range_name', 'label', 'service', 'prefix')
_COUNTRY_KEYS = ('country', 'country_name', 'countryName')
_EXTRA_KEYS = ('count', 'available', 'stock', 'total', 'rate')
_CONTAINER_KEYS = ('ranges', 'range_list', 'rangeList', 'range_data', 'rangeData', 'country_ranges', 'countryRanges', 'available_ranges', 'availableRanges', 'items', 'list', 'results', 'result', 'data', 'payload', 'response', 'records', 'rows', 'countries', 'country_list', 'countryList', 'numbers', 'prefixes', 'services')
_META_KEYS = {'meta', 'message', 'rid', 'status', 'code', 'success', 'error', 'detail'}
_SCALAR = (str, int)
RANGE_PAGE_SIZE = 40
RANGE_CACHE = {}  # uid -> [(rid, label)] for the page buttons (in-memory only)


def _is_scalar(v):
    return isinstance(v, _SCALAR) and not isinstance(v, bool) and str(v).strip() != ''


def _range_label(rid, country, name, extra):
    parts = []
    if country and str(country) != rid:
        parts.append(str(country))
    if name and str(name) != rid and str(name) != str(country):
        parts.append(str(name))
    label = ' - '.join(parts)
    label = f'{label} ({rid})' if label else rid
    if extra is not None:
        label += f' • {extra}'
    return label[:40]


def parse_ranges(payload):
    """Return [(rid, label)] from /ranges responses.

    Handles flat lists AND country-grouped shapes, for example:
      {"data": [{"rid": "26134", "name": "..."}]}
      {"data": {"ranges": [...]}}
      {"data": [{"country": "Bangladesh", "ranges": [{"rid": "26134"}]}]}
      {"data": {"Bangladesh": [{"rid": "26134"}, ...], "India": [...]}}
      {"data": {"26134": "Bangladesh 01"}}   (rid -> name mapping)
    Never raises on unexpected shapes; returns [] if no range id can be found.
    """
    out, seen = [], set()

    def value(item, keys):
        """Read known provider fields without depending on their capitalization."""
        if not isinstance(item, dict):
            return None
        wanted = {str(key).lower() for key in keys}
        for key, val in item.items():
            if str(key).lower() in wanted and val not in (None, ''):
                return val
        return None

    def is_nested(node):
        if isinstance(node, (dict, list)):
            return bool(node)
        if isinstance(node, str) and node.strip().startswith(('{', '[')):
            try:
                return isinstance(json.loads(node), (dict, list))
            except (TypeError, ValueError):
                return False
        return False

    def add(rid, country, name, extra):
        rid = str(rid).strip()
        if not rid or rid in seen or len(f'getnum_{rid}'.encode()) > 64:
            return
        seen.add(rid)
        out.append((rid, _range_label(rid, country, name, extra)))

    def leaf(item, ctx, rid_hint=None):
        rid = value(item, _RID_KEYS)
        if not _is_scalar(rid):
            rid = value(item, ('id',))
        if not _is_scalar(rid):
            rid = rid_hint
        if rid is None:
            return False
        country = value(item, _COUNTRY_KEYS) or ctx
        name = value(item, _NAME_KEYS)
        extra = value(item, _EXTRA_KEYS)
        add(rid, country if _is_scalar(country) else ctx, name if _is_scalar(name) else None,
            extra if _is_scalar(extra) else None)
        return True

    def walk(node, ctx=None, depth=0, rid_hint=None):
        if depth > 20:
            return
        if isinstance(node, str):
            text = node.strip()
            if text.startswith(('{', '[')):
                try:
                    decoded = json.loads(text)
                except (TypeError, ValueError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    walk(decoded, ctx, depth + 1, rid_hint)
            return
        if isinstance(node, list):
            for item in node:
                if is_nested(item):
                    walk(item, ctx, depth + 1, rid_hint)
                elif _is_scalar(item) and re.fullmatch(r'[\w\-:.]+', str(item).strip()):
                    add(str(item).strip(), ctx, None, None)
            return
        if not isinstance(node, dict):
            return
        # A dict holding a nested list/dict of ranges is a group (country), not a range itself
        children = {str(k).lower(): k for k in node}
        child = next((children[k.lower()] for k in _CONTAINER_KEYS
                      if k.lower() in children and is_nested(node[children[k.lower()]])), None)
        if child:
            group = value(node, _COUNTRY_KEYS + _NAME_KEYS)
            walk(node[child], group if _is_scalar(group) else ctx, depth + 1, rid_hint)
            return
        if leaf(node, ctx, rid_hint):
            return
        # Mapping style: {"Bangladesh": [...]} or {"26134": {"name": "Bangladesh 01"}}
        for k, v in node.items():
            key = str(k).strip()
            if key.lower() in _META_KEYS:
                continue
            if is_nested(v):
                if key.isdigit():
                    walk(v, ctx, depth + 1, key)
                else:
                    walk(v, key, depth + 1, rid_hint)
            elif _is_scalar(v) and re.fullmatch(r'[\w\-:.]+', key) and key.isdigit():
                add(key, ctx, str(v), None)

    walk(payload)
    return out


def ranges_keyboard(ranges, page=0):
    """Two-column range buttons for one page, with Prev/Next when there are more than RANGE_PAGE_SIZE."""
    pages = max(1, (len(ranges) + RANGE_PAGE_SIZE - 1) // RANGE_PAGE_SIZE)
    page = min(max(page, 0), pages - 1)
    rows, row = [], []
    for rid, label in ranges[page * RANGE_PAGE_SIZE:(page + 1) * RANGE_PAGE_SIZE]:
        row.append(InlineKeyboardButton(label, callback_data=f'getnum_{rid}'))
        if len(row) == 2:
            rows.append(row); row = []
    if row: rows.append(row)
    if pages > 1:
        nav = []
        if page > 0: nav.append(InlineKeyboardButton('⬅ Prev', callback_data=f'rpage_{page - 1}'))
        nav.append(InlineKeyboardButton(f'{page + 1}/{pages}', callback_data='rpage_noop'))
        if page < pages - 1: nav.append(InlineKeyboardButton('Next ➡', callback_data=f'rpage_{page + 1}'))
        rows.append(nav)
    return InlineKeyboardMarkup(rows)


async def show_ranges(message, uid):
    """GET NUMBER: load the ranges available for this user's TGZ key and show them as buttons."""
    try:
        headers = {'mauthapi': provider_key_for(uid)}
    except Exception:
        logger.exception('provider key decrypt failed')
        await message.reply_text('Provider key error. Please contact admin.'); return
    ranges, problem = [], None
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(PROVIDER_BASE + '/ranges', headers=headers)
        logger.info('ranges %s %s', response.status_code, response.text[:500])
        try:
            payload = response.json()
        except ValueError:
            payload = None
            problem = f'Provider returned a non-JSON response (HTTP {response.status_code}).'
        if payload is not None:
            if response.status_code >= 400:
                text = (payload.get('message') or payload.get('detail')) if isinstance(payload, dict) else None
                problem = f'Provider error (HTTP {response.status_code}): {str(text or "request failed")[:150]}'
                if response.status_code == 429:
                    problem += '\nThe TGZ API key used by the bot reached its rate limit. Admin: raise it with /adminlimit or wait one minute.'
                if response.status_code in (401, 403) and uid in ADMIN_IDS and provider_base_is_own_api():
                    problem += '\n\n' + OWN_API_HINT
            else:
                meta = next((value for key, value in payload.items() if str(key).lower() == 'meta'), None) if isinstance(payload, dict) else None
                meta_code = next((value for key, value in meta.items() if str(key).lower() == 'code'), 200) if isinstance(meta, dict) else 200
                meta_status = next((value for key, value in meta.items() if str(key).lower() == 'status'), None) if isinstance(meta, dict) else None
                if meta_code in (None, ''):
                    meta_code = 200
                success_codes = {'200', '0', 'ok', 'success', 'true'}
                meta_failed = str(meta_code).strip().lower() not in success_codes
                if meta_status is not None and str(meta_status).strip().lower() in {'error', 'failed', 'failure', 'false'}:
                    meta_failed = True
                if meta_failed:
                    error_message = next((value for key, value in payload.items() if str(key).lower() in {'message', 'detail', 'error'}), '')
                    problem = f"Provider error (code {meta_code}): {str(error_message)[:150]}"
                else:
                    ranges = parse_ranges(payload)
                    if not ranges:
                        logger.error('ranges: no range id found in response: %s', response.text[:800])
                        problem = 'Provider answered, but no ranges were found in the response.'
    except Exception:
        logger.exception('ranges failed')
        problem = 'Could not reach the provider.'
    if not ranges:
        await message.reply_text(f'{problem or "No ranges available."}\nSend the range ID like this:\n/number 26134\n\nTo check your TGZ API connection use /diag')
        return
    RANGE_CACHE[uid] = ranges
    await message.reply_text('📱 Select a country range to get a number:', reply_markup=ranges_keyboard(ranges, 0))


async def deliver_number(message, uid, rid):
    """Get a number for `rid`, poll its OTP (about 75 seconds), then credit the balance once."""
    ensure_user(uid)  # balance credit UPDATEs the users row; it must exist
    try:
        headers = {'mauthapi': provider_key_for(uid)}
    except Exception:
        logger.exception('provider key decrypt failed')
        await message.reply_text('Provider key error. Please contact admin.'); return
    result = None; stop_reason = None
    async with httpx.AsyncClient(timeout=40, follow_redirects=True) as client:
        try:
            response = await client.post(PROVIDER_BASE + '/getnum', headers=headers, json={'rid': rid})
        except Exception:
            logger.exception('getnum request failed')
            await message.reply_text('Provider connection error, please try again. (Admin: run /diag)'); return
        try:
            data = response.json()
        except ValueError:
            logger.error('getnum non-JSON HTTP %s: %s', response.status_code, response.text[:300])
            await message.reply_text(f'Provider returned an invalid response (HTTP {response.status_code}).'); return
        logger.info('getnum HTTP %s: %s', response.status_code, str(data)[:300])
        details = data.get('data') if isinstance(data, dict) else None
        meta = data.get('meta') if isinstance(data, dict) else None
        meta_code = str(meta.get('code', 200)) if isinstance(meta, dict) else '200'
        if response.status_code >= 400 or meta_code != '200' or not isinstance(details, dict) or not details:
            reason = (data.get('message') or data.get('detail')) if isinstance(data, dict) else None
            await message.reply_text(f"Number unavailable: {reason or 'provider error'} (HTTP {response.status_code})"); return
        raw_number = _first_value(details, ('no_plus_number', 'full_number', 'number', 'phone'))
        num = _normalise_number(raw_number)
        if not num:
            logger.error('getnum returned no usable number: %s', str(details)[:200])
            await message.reply_text('Provider returned no number.'); return
        shown = details.get('full_number') or f'+{num}'
        with engine.begin() as c:
            # If TGZ_API_BASE points at this project's own API, /getnum already created the allocation
            # row for this number. Reuse it (linked for 30 minutes) so there is one row and one credit.
            existing = c.execute(select(allocations.c.id).where(
                allocations.c.tg_id == uid, allocations.c.number == num, allocations.c.status == 'allocated',
                allocations.c.created_at >= now() - timedelta(minutes=30),
            ).order_by(allocations.c.id.desc())).first()
            if existing:
                allocation_id = existing[0]
            else:
                allocation_id = c.execute(allocations.insert().values(tg_id=uid, number=num, rid=str(rid), created_at=now(), status='allocated')).inserted_primary_key[0]
        await message.reply_text(f"📞 Number: {shown}\nWaiting for OTP (up to about 75 seconds)...")
        for _ in range(3):
            try:
                r = await client.get(PROVIDER_BASE + '/otp', headers=headers, params={'number': num, 'wait': 25})
                logger.info('otp HTTP %s: %s', r.status_code, r.text[:300])
                if r.status_code in (401, 403, 404):
                    # number expired / not owned / key problem: further polling cannot succeed
                    try:
                        stop_reason = str((r.json() or {}).get('message') or r.status_code)
                    except Exception:
                        stop_reason = f'HTTP {r.status_code}'
                    break
                result = extract_otp(r.json(), number=num) if r.status_code < 400 else None
            except Exception:
                logger.exception('otp poll failed')
            if result: break
            await asyncio.sleep(2)
    if not result:
        await message.reply_text(f'OTP stopped: {stop_reason}' if stop_reason else 'No OTP arrived within the wait window.'); return
    with engine.begin() as c:
        c.execute(sqlalchemy_update(allocations).where(allocations.c.id == allocation_id).values(otp=result['otp'], service=result.get('service'), status='success'))
    service_text = f"\nService: {result['service']}" if result.get('service') else ''
    await message.reply_text(f"OTP: {result['otp']}{service_text}")
    try:
        credited = credit_otp_balance(uid, allocation_id, result.get('service'))
        if credited:
            await message.reply_text(f'Added to balance: {paisa_to_bdt(credited)} BDT')
        else:
            await message.reply_text('This OTP is already credited to your balance.')
    except Exception:
        logger.exception('credit_otp_balance failed')
        await message.reply_text('OTP received, but balance credit failed. Please contact admin.')

async def number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id; ensure_user(uid)
    if not context.args:
        await show_ranges(update.message, uid); return
    await deliver_number(update.message, uid, context.args[0])


async def diag(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shows exactly what the TGZ provider answers for this user's key (no key is displayed)."""
    uid = update.effective_user.id; ensure_user(uid)
    lines = [f'Key in use: {provider_key_source(uid)}']
    if uid in ADMIN_IDS:
        lines.append(f'Provider base: {PROVIDER_BASE}')
        if provider_base_is_own_api():
            lines.append('Note: provider base = this project\'s own API.\n' + OWN_API_HINT)
    try:
        headers = {'mauthapi': provider_key_for(uid)}
    except Exception as exc:
        await update.message.reply_text('\n'.join(lines + [f'Key decrypt error: {exc}'])); return
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        for path in ('/balance', '/ranges'):
            try:
                r = await client.get(PROVIDER_BASE + path, headers=headers)
                lines.append(f'\nGET {path} -> HTTP {r.status_code}\n{r.text[:250 if path != "/ranges" else 900]}')
                if path == '/ranges':
                    try: lines.append(f'Parsed ranges: {len(parse_ranges(r.json()))}')
                    except Exception: lines.append('Parsed ranges: 0 (response is not valid JSON)')
            except Exception as exc:
                lines.append(f'\nGET {path} -> failed: {exc}')
    await update.message.reply_text('\n'.join(lines)[:3900])


async def show_key(message, uid, force=False):
    r = user_row(uid)
    if r and r['api_hash'] and not force:
        await message.reply_text(f"Active key prefix: `{r['api_prefix']}`\nUse COPY API KEY to receive the full key again only if it is available in this session. Use REGENERATE KEY to create a new key.", parse_mode='Markdown')
    else:
        key = generate_key(uid)
        await message.reply_text(f"Your new API key (save it now):\n`{key}`\n\nThe database stores only its hash.", parse_mode='Markdown')

async def _menu_impl(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer(); uid = q.from_user.id; ensure_user(uid, q.from_user.username, q.from_user.full_name); r = user_row(uid)
    if q.data == 'key': await show_key(q.message, uid)
    elif q.data == 'copy':
        if uid in ISSUED_KEYS: await q.message.reply_text(f"Your API key:\n`{ISSUED_KEYS[uid]}`", parse_mode='Markdown')
        elif r and r['api_hash']: await q.message.reply_text('For security, old keys cannot be reconstructed after a worker restart. Use REGENERATE KEY to receive a new copyable key.')
        else: await show_key(q.message, uid)
    elif q.data == 'regen':
        revoke_all_keys(uid); await show_key(q.message, uid, force=True)
    elif q.data == 'docs': await send_api_document(q.message, uid, username=q.from_user.username)
    elif q.data == 'test':
        if not PUBLIC_API_BASE: await q.message.reply_text('Set PUBLIC_API_BASE on the worker to enable the one-tap API test.'); return
        if not r or not r['api_hash']: await q.message.reply_text('Generate an API key first.'); return
        await q.message.reply_text('API test result: use the external API key test from your client, because only the key hash is stored server-side.')
    elif q.data == 'status': await q.message.reply_text(f"API: {'Enabled' if r and r['enabled'] else 'Disabled'}\nBanned: {'Yes' if r and r['banned'] else 'No'}\nKey: {'Generated' if r and r['api_hash'] else 'Not generated'}\nBalance: {paisa_to_bdt(r['balance_paisa'] if r else 0)} BDT")
    elif q.data == 'usage':
        with engine.begin() as c:
            total = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid)).scalar_one()
            recent = c.execute(select(api_usage.c.method, api_usage.c.path, api_usage.c.status_code, api_usage.c.created_at).where(api_usage.c.tg_id == uid).order_by(api_usage.c.id.desc()).limit(10)).mappings().all()
        await q.message.reply_text(f"Total API requests: {total}\n\n" + ('\n'.join(f"{x['method']} {x['path']} -> {x['status_code']}" for x in recent) or 'No API usage yet.'))
    elif q.data == 'allocations':
        with engine.begin() as c: rows = c.execute(select(allocations.c.number, allocations.c.rid, allocations.c.status).where(allocations.c.tg_id == uid).order_by(allocations.c.id.desc()).limit(20)).mappings().all()
        await q.message.reply_text('\n'.join(f"{x['number']} | range={x['rid']} | {x['status']}" for x in rows) or 'No allocations yet.')
    elif q.data == 'rpage_noop':
        pass
    elif q.data.startswith('rpage_'):
        cached = RANGE_CACHE.get(uid)
        if not cached:
            await q.message.reply_text('Range list expired. Press GET NUMBER again.'); return
        try: page = int(q.data.split('_', 1)[1])
        except ValueError: return
        await q.message.edit_reply_markup(reply_markup=ranges_keyboard(cached, page))
    elif q.data.startswith('getnum_'):
        await deliver_number(q.message, uid, q.data.replace('getnum_', '', 1))
    elif q.data == 'admin_close':
        await q.message.edit_text('Admin panel closed.')
    elif q.data == 'doc_close':
        await q.message.edit_text('API document closed.')
    elif q.data == 'doc_regen':
        await send_api_document(q.message, uid, force=True, username=q.from_user.username)
    elif q.data == 'doc_test':
        ensure_document_key(uid)
        if not PUBLIC_API_BASE:
            await q.message.reply_text('Test unavailable: PUBLIC_API_BASE is not configured.')
        else:
            try:
                async with httpx.AsyncClient(timeout=20) as client:
                    response = await client.get(PUBLIC_API_BASE + '/api/v1/me', headers={'mauthapi': ISSUED_KEYS[uid]})
                hint = ''
                if response.status_code == 429:
                    hint = '\n\nRate limit reached for this key. Wait one minute, or an admin can raise it with /adminlimit <telegram_id> <per_minute> <per_day> <getnum_per_day>.'
                elif response.status_code == 401:
                    hint = '\n\nThis key is not valid any more. Press Regenerate Key.'
                await q.message.reply_text(f'Test API: HTTP {response.status_code}\n{response.text[:1800]}{hint}')
            except Exception as exc:
                await q.message.reply_text(f'Test API failed: {exc}')
    elif q.data == 'admin_system':
        await q.message.reply_text('⚙️ SYSTEM SETTINGS\nChoose a system section:', reply_markup=system_settings_keyboard())
    elif q.data == 'settings_back':
        await q.message.edit_text('📊 ADMIN PANEL', reply_markup=admin_keyboard())
    elif q.data == 'settings_stex':
        await q.message.reply_text('🔐 STEXSMS CONTROL\n/setproviderkey <provider_key> saves the admin fallback key encrypted.\nThe provider base is configured by PROVIDER_API_BASE.')
    elif q.data == 'settings_join':
        await q.message.reply_text('👥 FORCE JOIN SYSTEM\nForce-join is not enabled in this deployment. Configure a verified channel and bot admin permission before enabling it.')
    elif q.data == 'settings_admins':
        await q.message.reply_text('🛡 ADMIN MANAGEMENT\nConfigured admin IDs:\n' + ('\n'.join(str(x) for x in sorted(ADMIN_IDS)) or 'None'))
    elif q.data == 'settings_otpgroup':
        group = os.getenv('OTP_GROUP_ID', '')
        await q.message.reply_text(f'📨 OTP GROUP\nConfigured group: {group or "Not configured"}\nSet OTP_GROUP_ID in Render Environment to configure a group.')
    elif q.data == 'settings_users':
        with engine.begin() as c:
            total = c.execute(select(func.count()).select_from(users)).scalar_one()
            active = c.execute(select(func.count()).select_from(users).where(users.c.enabled == True, users.c.banned == False)).scalar_one()
            banned = c.execute(select(func.count()).select_from(users).where(users.c.banned == True)).scalar_one()
        await q.message.reply_text(f'👤 USER MANAGEMENT\nTotal: {total}\nActive: {active}\nBanned: {banned}\n\nUse /adminaction ban|unban|enable|disable|revoke <telegram_id>.')
    elif q.data in {'lb_all', 'lb_weekly'}:
        await show_leaderboard(q.message, uid, 'weekly' if q.data == 'lb_weekly' else 'all', edit=True, bot=context.bot)
    elif q.data == 'lb_refresh':
        mode = (LEADERBOARD_STATE.get(uid) or {}).get('mode', 'all')
        await show_leaderboard(q.message, uid, mode, edit=True, bot=context.bot)
    elif q.data == 'lb_my_rank':
        mode = (LEADERBOARD_STATE.get(uid) or {}).get('mode', 'all')
        personal = leaderboard_personal(uid, mode)
        if personal:
            text = (f"👤 YOUR {'WEEKLY ' if mode == 'weekly' else ''}RANK\n\n"
                    f"Rank: #{personal['rank']}\nSuccessful OTPs: {personal['otp_count']}\n"
                    f"Earnings: {paisa_to_bdt(personal['earnings_paisa'])} BDT")
        else:
            text = '👤 YOUR RANK\n\nNo successful OTP earnings recorded for you yet.'
        await q.message.edit_text(text, reply_markup=leaderboard_keyboard(mode))
    elif q.data == 'lb_back':
        cancel_leaderboard(uid)
        await q.message.edit_text('Leaderboard closed.')
        await context.bot.send_message(uid, 'Choose an option below:', reply_markup=user_keyboard(uid))
    elif q.data == 'wd_open':
        if get_tgz_setting('withdraw_enabled', 'on').lower() not in {'on', 'true', '1'}:
            await q.message.reply_text('Withdrawal System is currently OFF.')
        elif not withdrawal_methods():
            await q.message.reply_text('No withdrawal method is configured by admin.')
        else:
            row = user_row(uid); minimum = int(get_tgz_setting('min_withdraw_paisa', '5000'))
            if not row or int(row['balance_paisa'] or 0) < minimum:
                await q.message.reply_text(f'Your balance must be at least {paisa_to_bdt(minimum)} BDT to withdraw.')
            else:
                PENDING_WITHDRAWALS[uid] = {}
                await q.message.edit_text('Select a withdrawal method:', reply_markup=withdrawal_method_keyboard())
    elif q.data.startswith('wd_method_'):
        try: index = int(q.data.rsplit('_', 1)[1]); method = withdrawal_methods()[index]
        except (ValueError, IndexError):
            await q.message.reply_text('Invalid withdrawal method. Please open Withdrawal again.'); return
        PENDING_WITHDRAWALS[uid] = {'method': method, 'stage': 'amount'}
        await q.message.edit_text(f'Method selected: {method}\n\nSend the withdrawal amount in BDT.')
    elif q.data == 'wd_confirm':
        state = PENDING_WITHDRAWALS.get(uid) or {}
        if state.get('stage') != 'confirm':
            await q.message.reply_text('This withdrawal session expired. Please start again.'); return
        if state.get('submitting'):
            await q.answer('Already submitting...', show_alert=False); return
        state['submitting'] = True
        try:
            wid = reserve_withdrawal(uid, q.from_user.username, state['amount_paisa'], state['method'], state['payment_info'])
            PENDING_WITHDRAWALS.pop(uid, None)
            row = get_withdrawal(wid)
            await q.message.edit_text(f'✅ Withdrawal Request Submitted\n\nWithdrawal ID: {wid}\nAmount: {paisa_to_bdt(row["amount_paisa"])} BDT\nStatus: Pending')
            await notify_withdrawal_admins(context.bot, row)
        except Exception as exc:
            state['submitting'] = False
            logger.exception('Withdrawal submission failed')
            await q.message.reply_text(f'Withdrawal could not be submitted: {str(exc)[:300]}')
    elif q.data == 'wd_cancel':
        PENDING_WITHDRAWALS.pop(uid, None)
        await q.message.edit_text('Withdrawal cancelled.', reply_markup=withdrawal_keyboard())
    elif q.data == 'wd_history':
        await q.message.edit_text(withdrawal_history_text(withdrawal_history(uid)), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('🔙 BACK', callback_data='wd_back')]]))
    elif q.data == 'wd_back':
        PENDING_WITHDRAWALS.pop(uid, None)
        await q.message.edit_text(withdrawal_main_text(uid), reply_markup=withdrawal_keyboard())
    elif q.data == 'wd_admin_list':
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            rows = admin_withdrawals()
            await q.message.edit_text(withdrawal_admin_list_text(rows), reply_markup=withdrawal_admin_keyboard(rows))
    elif q.data.startswith('wd_admin_view_'):
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            wid = q.data.replace('wd_admin_view_', '', 1); row = get_withdrawal(wid)
            if not row: await q.message.reply_text('Withdrawal request not found.')
            else:
                payment = decrypt(row['payment_info_encrypted'])
                detail = (f"💸 WITHDRAWAL DETAILS\n\nID: {row['withdrawal_id']}\nUser ID: {row['tg_id']}\nUsername: @{row['username'] or '-'}\n"
                          f"Amount: {paisa_to_bdt(row['amount_paisa'])} BDT\nMethod: {row['method']}\nPayment: {payment}\n"
                          f"Status: {withdrawal_status_label(row['status'])}\nRequested: {row['requested_at']}")
                if row['rejection_reason']: detail += f"\nReason: {row['rejection_reason']}"
                await q.message.edit_text(detail, reply_markup=withdrawal_admin_action_keyboard(row))
    elif q.data.startswith('wd_admin_approve_'):
        if uid not in ADMIN_IDS: await q.message.reply_text('Not authorized.')
        else:
            wid = q.data.replace('wd_admin_approve_', '', 1); changed, status = approve_withdrawal(wid, uid)
            row = get_withdrawal(wid)
            if changed and row:
                await context.bot.send_message(row['tg_id'], f'✅ Withdrawal {wid} approved.\nAmount: {paisa_to_bdt(row["amount_paisa"])} BDT\nStatus: Approved')
            await q.message.reply_text(f'{wid}: {"Approved" if changed else "No change; current status is " + status}.')
    elif q.data.startswith('wd_admin_paid_'):
        if uid not in ADMIN_IDS: await q.message.reply_text('Not authorized.')
        else:
            wid = q.data.replace('wd_admin_paid_', '', 1); changed, status = mark_withdrawal_paid(wid, uid)
            row = get_withdrawal(wid)
            if changed and row:
                await context.bot.send_message(row['tg_id'], f'💰 Withdrawal {wid} marked as paid.\nAmount: {paisa_to_bdt(row["amount_paisa"])} BDT\nStatus: Paid')
            await q.message.reply_text(f'{wid}: {"Marked as Paid" if changed else "No change; current status is " + status}.')
    elif q.data.startswith('wd_admin_reject_'):
        if uid not in ADMIN_IDS: await q.message.reply_text('Not authorized.')
        else:
            wid = q.data.replace('wd_admin_reject_', '', 1); PENDING_ADMIN_REJECTIONS[uid] = wid
            await q.message.reply_text(f'Send rejection reason for {wid}. Send CANCEL to cancel.')
    elif q.data == 'settings_tgz':
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            await q.message.reply_text(tgz_control_panel_message(), reply_markup=tgz_control_keyboard())
    elif q.data.startswith('tgz_edit_'):
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            key = q.data.replace('tgz_edit_', '', 1)
            prompts = {
                'min_withdraw': 'Send minimum withdrawal amount in BDT, for example: 50',
                'otp_reward': 'Send OTP reward in BDT, for example: 0.4',
                'refer_reward': 'Send referral reward in BDT, for example: 0.2',
                'cooldown': 'Send cooldown seconds, for example: 10',
                'num_req': 'Send NUM/REQ value, for example: 3',
                'num_share': 'Send NUM/SHARE value, for example: 1',
                'w_methods': 'Send withdrawal methods separated by commas, for example: bKash,Nagad,Rocket',
                'api_url': 'Send API URL or AUTO, for example: AUTO',
            }
            if key not in prompts:
                await q.message.reply_text('Unknown TGZ setting.')
            else:
                PENDING_TGZ_SETTINGS[uid] = key
                await q.message.reply_text(f"{prompts[key]}\nSend CANCEL to cancel this input.")
    elif q.data in {'tgz_toggle_withdraw', 'tgz_toggle_support', 'tgz_toggle_w_group'}:
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            setting_name = {'tgz_toggle_withdraw': 'withdraw_enabled', 'tgz_toggle_support': 'support_link_enabled', 'tgz_toggle_w_group': 'withdraw_group_enabled'}[q.data]
            current = get_tgz_setting(setting_name, 'off').lower()
            set_tgz_setting(setting_name, 'off' if current in {'on', 'true', '1'} else 'on', uid)
            await q.message.edit_text(tgz_control_panel_message(), reply_markup=tgz_control_keyboard())
    elif q.data == 'settings_emoji':
        await q.message.reply_text('💎 PREMIUM EMOJI\nButton colours (blue / green / red) use the native Telegram button styles and need an up-to-date Telegram app.')
    elif q.data == 'settings_menu':
        await q.message.reply_text('🎨 MENU DESIGN\nCurrent design: coloured reply keyboard (blue / green / red) with API DOCUMENT, BALANCE, STATUS, and Admin Panel.')
    elif q.data == 'settings_test':
        await q.message.reply_text((await dashboard_text(uid)) + '\n\n✅ Database module loaded\n✅ API routes available\n✅ Telegram handlers loaded\n✅ Provider configuration loaded')
    elif q.data == 'admin_users':
        with engine.begin() as c:
            rows = c.execute(select(users.c.tg_id, users.c.enabled, users.c.banned, users.c.api_prefix).order_by(users.c.created_at.desc()).limit(50)).mappings().all()
        await q.message.reply_text('\n'.join(f"{x['tg_id']} | enabled={x['enabled']} banned={x['banned']} key={x['api_prefix'] or '-'}" for x in rows) or 'No API users yet.')
    elif q.data == 'admin_used':
        with engine.begin() as c:
            rows = c.execute(select(allocations.c.number, allocations.c.tg_id, allocations.c.status).where(allocations.c.status.in_(['allocated', 'success'])).order_by(allocations.c.id.desc()).limit(50)).mappings().all()
        await q.message.reply_text('\n'.join(f"{x['number']} | user={x['tg_id']} | {x['status']}" for x in rows) or 'No used numbers.')
    elif q.data == 'admin_unused':
        await q.message.reply_text('Unused inventory is provider-managed. Use the provider ranges endpoint to view available stock.')
    elif q.data == 'admin_otprate':
        if uid not in ADMIN_IDS:
            await q.message.reply_text('Not authorized.')
        else:
            with engine.begin() as c:
                rows = c.execute(select(otp_rates).order_by(otp_rates.c.service)).mappings().all()
            rate_text = '\n'.join(f"{x['service']}: {paisa_to_bdt(x['rate_paisa'])} BDT" for x in rows) or 'No OTP rates configured.'
            await q.message.reply_text(f"OTP RATES\n{rate_text}\n\nChange: /setotprate <amount_bdt> [SERVICE]\nExample: /setotprate 1.50 FACEBOOK")
    elif q.data == 'admin_upload':
        await q.message.reply_text('Number upload is not enabled because this project allocates numbers from the configured provider. Use API DOCUMENT or /number <range_id>.')
    elif q.data == 'admin_delete':
        await q.message.reply_text('Delete is disabled in this safe panel so existing allocation history cannot be destroyed. Use /adminaction revoke <telegram_id> to revoke a user key.')
    elif q.data == 'admin_backup':
        await q.message.reply_text('Database backups are managed by Render PostgreSQL. Do not expose database credentials in chat.')
    elif q.data == 'admin_broadcast':
        await q.message.reply_text('Broadcast is disabled by default. Use an approved recipient list before enabling bulk messaging.')
    elif q.data == 'admin_addbot':
        await q.message.reply_text('Add Bot is not enabled in this deployment. Keep one polling process per Telegram bot token.')

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    try:
        await _menu_impl(update, context)
    except Exception as exc:
        logger.exception("Inline button callback failed; callback_data=%r",
                         getattr(q, "data", None))
        if q:
            try:
                await q.answer("Button error. Check bot logs.", show_alert=True)
            except Exception:
                pass
            try:
                if q.message:
                    await q.message.reply_text(
                        f"Button error: {type(exc).__name__}: {str(exc)[:700]}"
                    )
            except Exception:
                logger.exception("Could not send callback error to user")


async def telegram_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled Telegram update error", exc_info=context.error)
    try:
        if isinstance(update, Update) and update.effective_message:
            await update.effective_message.reply_text(
                f"Bot error: {type(context.error).__name__}: {str(context.error)[:700]}"
            )
    except Exception:
        logger.exception("Could not send update error to user")


async def regenerate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id; revoke_all_keys(uid); await show_key(update.message, uid, force=True)

async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: await update.message.reply_text('Not authorized.'); return
    with engine.begin() as c: rows = c.execute(select(users.c.tg_id, users.c.enabled, users.c.banned, users.c.api_prefix).order_by(users.c.created_at.desc()).limit(50)).mappings().all()
    await update.message.reply_text('\n'.join(f"{r['tg_id']} | enabled={r['enabled']} banned={r['banned']} key={r['api_prefix'] or '-'}" for r in rows) or 'No API users yet.')

async def adminstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: await update.message.reply_text('Not authorized.'); return
    with engine.begin() as c:
        total = c.execute(select(func.count()).select_from(users)).scalar_one(); active = c.execute(select(func.count()).select_from(users).where(users.c.enabled == True, users.c.banned == False)).scalar_one(); disabled = c.execute(select(func.count()).select_from(users).where(users.c.enabled == False)).scalar_one(); requests = c.execute(select(func.count()).select_from(api_usage)).scalar_one(); credited = c.execute(select(func.coalesce(func.sum(balance_transactions.c.amount_paisa), 0)).where(balance_transactions.c.transaction_type == 'otp_credit')).scalar_one()
    await update.message.reply_text(f'Total users: {total}\nActive: {active}\nDisabled: {disabled}\nAPI requests: {requests}\nOTP credited: {paisa_to_bdt(credited)} BDT')


async def set_otp_rate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or not context.args or len(context.args) > 2:
        await update.message.reply_text('Usage: /setotprate <amount_bdt> [SERVICE]\nExample: /setotprate 1.50 FACEBOOK')
        return
    try:
        rate_paisa = bdt_to_paisa(context.args[0])
        if rate_paisa <= 0:
            raise ValueError
    except (InvalidOperation, ValueError):
        await update.message.reply_text('Rate must be a positive amount, for example 1.50.')
        return
    service = (context.args[1].strip() if len(context.args) == 2 else '__default__') or '__default__'
    with engine.begin() as c:
        existing = c.execute(select(otp_rates.c.service).where(otp_rates.c.service == service)).first()
        values = {'rate_paisa': rate_paisa, 'enabled': True, 'updated_by': update.effective_user.id, 'updated_at': now()}
        if existing:
            c.execute(sqlalchemy_update(otp_rates).where(otp_rates.c.service == service).values(**values))
        else:
            c.execute(otp_rates.insert().values(service=service, **values))
    if service == '__default__':
        set_tgz_setting('otp_reward_paisa', rate_paisa, update.effective_user.id)
    await update.message.reply_text(f'OTP rate updated: {service} = {paisa_to_bdt(rate_paisa)} BDT')


async def otp_rates_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text('Not authorized.')
        return
    with engine.begin() as c:
        rows = c.execute(select(otp_rates).order_by(otp_rates.c.service)).mappings().all()
    await update.message.reply_text('\n'.join(f"{x['service']}: {paisa_to_bdt(x['rate_paisa'])} BDT" for x in rows) or 'No OTP rates configured.')


async def set_tgz_control(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or len(context.args) < 2:
        await update.message.reply_text('Usage: /settgzcontrol <KEY> <VALUE>\nExample: /settgzcontrol otp_reward 0.4')
        return
    key = context.args[0].lower()
    if key not in TGZ_SETTING_KEYS:
        await update.message.reply_text('Unknown key. Use /tgzcontrol to see valid keys.')
        return
    setting_name = TGZ_SETTING_KEYS[key]
    raw_value = ' '.join(context.args[1:]).strip()
    try:
        if key in {'withdraw', 'support', 'w_group'}:
            value = raw_value.lower()
            if value not in {'on', 'off'}:
                raise ValueError('Use ON or OFF.')
        elif key in {'min_withdraw', 'otp_reward', 'refer_reward'}:
            paisa = bdt_to_paisa(raw_value)
            if paisa <= 0:
                raise ValueError('Amount must be positive.')
            value = str(paisa)
        elif key in {'cooldown', 'num_req', 'num_share'}:
            value = str(int(raw_value))
            if int(value) < 0 or (key != 'cooldown' and int(value) < 1):
                raise ValueError('Invalid number.')
        elif key == 'api_url':
            value = raw_value if raw_value.upper() == 'AUTO' else raw_value.rstrip('/')
            if value.upper() != 'AUTO' and not re.match(r'^https?://', value):
                raise ValueError('API URL must start with http:// or https://, or be AUTO.')
            value = value.upper() if value == 'AUTO' else value
        else:
            value = raw_value
    except (InvalidOperation, ValueError) as exc:
        await update.message.reply_text(f'Invalid value: {exc}')
        return
    set_tgz_setting(setting_name, value, update.effective_user.id)
    if key == 'otp_reward':
        with engine.begin() as c:
            c.execute(sqlalchemy_update(otp_rates).where(otp_rates.c.service == '__default__').values(rate_paisa=int(value), updated_by=update.effective_user.id, updated_at=now()))
    await update.message.reply_text(f'Updated {key}: {paisa_to_bdt(value) if key in {"min_withdraw", "otp_reward", "refer_reward"} else value}')


async def tgz_control_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text('Not authorized.')
        return
    await update.message.reply_text(tgz_control_panel_message(), reply_markup=tgz_control_keyboard())

async def admin_action(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or len(context.args) < 1: await update.message.reply_text('Usage: /adminaction <ban|unban|enable|disable|revoke> <telegram_id>'); return
    try: uid = int(context.args[1] if len(context.args) > 1 else context.args[0]); action = context.args[0]
    except ValueError: await update.message.reply_text('Invalid Telegram ID.'); return
    with engine.begin() as c:
        if action == 'ban': c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(banned=True))
        elif action == 'unban': c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(banned=False))
        elif action == 'enable': c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(enabled=True))
        elif action == 'disable': c.execute(sqlalchemy_update(users).where(users.c.tg_id == uid).values(enabled=False))
        elif action == 'revoke': revoke_all_keys(uid)
        else: await update.message.reply_text('Unknown action.'); return
    await update.message.reply_text(f'{action} completed for {uid}.')

async def admin_limit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or len(context.args) != 4:
        await update.message.reply_text('Usage: /adminlimit <telegram_id> <per_minute> <per_day> <getnum_per_day>'); return
    try:
        uid, per_minute, per_day, getnum_per_day = (int(x) for x in context.args)
        if min(per_minute, per_day, getnum_per_day) < 1: raise ValueError
    except ValueError:
        await update.message.reply_text('All values must be positive integers.'); return
    with engine.begin() as c:
        existing = c.execute(select(rate_limits.c.tg_id).where(rate_limits.c.tg_id == uid)).first()
        values = {'per_minute': per_minute, 'per_day': per_day, 'getnum_per_day': getnum_per_day, 'updated_at': now()}
        if existing: c.execute(sqlalchemy_update(rate_limits).where(rate_limits.c.tg_id == uid).values(**values))
        else: c.execute(rate_limits.insert().values(tg_id=uid, **values))
    await update.message.reply_text(f'Rate limit updated for {uid}.')

async def admin_permission(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or len(context.args) != 3:
        await update.message.reply_text('Usage: /adminpermission <telegram_id> <permission> <on|off>'); return
    try: uid = int(context.args[0])
    except ValueError: await update.message.reply_text('Invalid Telegram ID.'); return
    permission, enabled_text = context.args[1], context.args[2].lower()
    if enabled_text not in {'on', 'off'}: await update.message.reply_text('Use on or off.'); return
    with engine.begin() as c:
        c.execute(api_permissions.insert().values(tg_id=uid, permission=permission, enabled=enabled_text == 'on', updated_at=now()))
    await update.message.reply_text(f'Permission {permission} set to {enabled_text} for {uid}.')

async def set_tgz_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id; ensure_user(uid)
    if len(context.args) != 1:
        await update.message.reply_text('Usage: /settgzkey <your_TGZ_API_key>'); return
    try: encrypted = encrypt(context.args[0])
    except RuntimeError as exc: await update.message.reply_text(str(exc)); return
    with engine.begin() as c:
        existing = c.execute(select(user_provider_keys.c.tg_id).where(user_provider_keys.c.tg_id == uid)).first()
        if existing: c.execute(sqlalchemy_update(user_provider_keys).where(user_provider_keys.c.tg_id == uid).values(key_encrypted=encrypted, enabled=True, updated_at=now()))
        else: c.execute(user_provider_keys.insert().values(tg_id=uid, key_encrypted=encrypted, provider='tgz', enabled=True, updated_at=now()))
    await update.message.reply_text('Your TGZ API key was encrypted and saved. /number will now use your TGZ balance.')

async def set_provider_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS or len(context.args) != 1:
        await update.message.reply_text('Usage: /setproviderkey <STEXSMS_or_TGZ_master_key>'); return
    try: encrypted = encrypt(context.args[0])
    except RuntimeError as exc: await update.message.reply_text(str(exc)); return
    with engine.begin() as c:
        existing = c.execute(select(provider_settings.c.name).where(provider_settings.c.name == 'provider_api_key')).first()
        if existing: c.execute(sqlalchemy_update(provider_settings).where(provider_settings.c.name == 'provider_api_key').values(value_encrypted=encrypted, updated_by=update.effective_user.id, updated_at=now()))
        else: c.execute(provider_settings.insert().values(name='provider_api_key', value_encrypted=encrypted, updated_by=update.effective_user.id, updated_at=now()))
    await update.message.reply_text('Admin provider API key saved encrypted on the server. It will be used when a user has no personal TGZ key.')

async def text_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id; ensure_user(uid, update.effective_user.username, update.effective_user.full_name); label = (update.message.text or '').strip()
    if uid in PENDING_ADMIN_REJECTIONS and uid in ADMIN_IDS:
        wid = PENDING_ADMIN_REJECTIONS.pop(uid)
        if label.upper() == 'CANCEL':
            await update.message.reply_text('Rejection cancelled.')
            return
        try:
            changed, status = reject_withdrawal(wid, uid, label[:500])
            row = get_withdrawal(wid)
            if changed and row:
                await context.bot.send_message(row['tg_id'], f'❌ Withdrawal {wid} was rejected.\nReason: {label[:500]}\nRefunded: {paisa_to_bdt(row["amount_paisa"])} BDT')
            await update.message.reply_text(f'{wid}: {"Rejected and balance refunded" if changed else "No change; current status is " + status}.')
        except Exception as exc:
            logger.exception('Withdrawal rejection failed')
            await update.message.reply_text(f'Rejection failed: {str(exc)[:300]}')
        return
    if uid in PENDING_WITHDRAWALS:
        state = PENDING_WITHDRAWALS[uid]
        if label.upper() == 'CANCEL':
            PENDING_WITHDRAWALS.pop(uid, None)
            await update.message.reply_text('Withdrawal cancelled.', reply_markup=withdrawal_keyboard())
            return
        if state.get('stage') == 'amount':
            try:
                amount_paisa = bdt_to_paisa(label)
                minimum = int(get_tgz_setting('min_withdraw_paisa', '5000'))
                row = user_row(uid); balance = int(row['balance_paisa'] if row else 0)
                if amount_paisa <= 0: raise ValueError('Amount must be greater than zero.')
                if amount_paisa < minimum: raise ValueError(f'Minimum withdrawal is {paisa_to_bdt(minimum)} BDT.')
                if amount_paisa > balance: raise ValueError('Amount cannot exceed your balance.')
                state.update(amount_paisa=amount_paisa, stage='payment')
                await update.message.reply_text(f'Amount: {paisa_to_bdt(amount_paisa)} BDT\nSend your {state["method"]} payment number or account information.')
            except (InvalidOperation, ValueError) as exc:
                await update.message.reply_text(f'Invalid amount: {exc}')
            return
        if state.get('stage') == 'payment':
            if not label or len(label) > 300:
                await update.message.reply_text('Payment information cannot be empty and must be under 300 characters.')
                return
            state.update(payment_info=label, stage='confirm')
            await update.message.reply_text(
                f'🔎 CONFIRM WITHDRAWAL\n\nMethod: {state["method"]}\nAmount: {paisa_to_bdt(state["amount_paisa"])} BDT\nPayment: {mask_payment_info(label)}\n\nSubmit this request?',
                reply_markup=withdrawal_confirm_keyboard(),
            )
            return
    if uid in PENDING_TGZ_SETTINGS and uid in ADMIN_IDS:
        if label.upper() == 'CANCEL':
            PENDING_TGZ_SETTINGS.pop(uid, None)
            await update.message.reply_text('TGZ setting update cancelled.', reply_markup=tgz_control_keyboard())
            return
        key = PENDING_TGZ_SETTINGS.pop(uid)
        try:
            value = apply_tgz_value(key, label, uid)
            shown = paisa_to_bdt(value) if key in {'min_withdraw', 'otp_reward', 'refer_reward'} else value
            await update.message.reply_text(f'{key} updated: {shown}', reply_markup=tgz_control_keyboard())
        except (InvalidOperation, ValueError) as exc:
            PENDING_TGZ_SETTINGS[uid] = key
            await update.message.reply_text(f'Invalid value: {exc}\nPlease send a valid value or CANCEL.')
        return
    if label in {'GET NUMBER', '2FA ONLINE'}:
        await show_ranges(update.message, uid)
    elif label == 'API DOCUMENT':
        await send_api_document(update.message, uid, username=update.effective_user.username)
    elif label == 'STATUS':
        r = user_row(uid); await update.message.reply_text(f"API: {'Enabled' if r and r['enabled'] else 'Disabled'}\nBanned: {'Yes' if r and r['banned'] else 'No'}\nKey: {'Generated' if r and r['api_hash'] else 'Not generated'}")
    elif label == 'BALANCE':
        r = user_row(uid)
        await update.message.reply_text(f"Your OTP balance: {paisa_to_bdt(r['balance_paisa'] if r else 0)} BDT")
    elif label == 'Admin Panel':
        if uid not in ADMIN_IDS: await update.message.reply_text('Not authorized.'); return
        await update.message.reply_text('📊 ADMIN PANEL', reply_markup=admin_keyboard())
    elif label == 'Leader Board':
        await show_leaderboard(update.message, uid, 'all', bot=context.bot)
    elif label == 'Refer':
        me = await context.bot.get_me()
        link = f'https://t.me/{me.username}?start=ref_{uid}' if me.username else 'Referral link unavailable'
        await update.message.reply_text(
            '➖➖➖➖➖➖➖\n'
            '« 🎁 REFER & EARN »\n'
            '➖➖➖➖➖➖➖\n'
            f'🔗 YOUR LINK:\n{link}\n'
            '➖➖➖➖➖➖➖\n'
            '👤 TOTAL REFERS: 0\n'
            '➖➖➖➖➖➖➖\n'
            f"💸 PER REFER: {paisa_to_bdt(get_tgz_setting('refer_reward_paisa', '20'))} BDT\n"
            '➖➖➖➖➖➖➖\n'
            '💸 OTP COMMISSION: 0.00 BDT\n'
            'COMMISSION OTPs: 0\n'
            'STATUS: ON (10%)\n'
            '━━━━━━━━━━━━')
    elif label == 'WITHDRAWAL':
        await update.message.reply_text(withdrawal_main_text(uid), reply_markup=withdrawal_keyboard())
    elif label == 'SUPPORT':
        if get_tgz_setting('support_link_enabled', 'on').lower() not in {'on', 'true', '1'}:
            await update.message.reply_text('Support link is currently OFF.')
        else:
            await update.message.reply_text(os.getenv('SUPPORT_LINK', 'Please contact the administrator for support.'))

def build_application():
    init_db(); application = Application.builder().token(BOT_TOKEN).concurrent_updates(True).build()
    application.add_handler(CommandHandler('start', start)); application.add_handler(CommandHandler('number', number)); application.add_handler(CommandHandler('diag', diag)); application.add_handler(CommandHandler('regenerate', regenerate)); application.add_handler(CommandHandler('settgzkey', set_tgz_key)); application.add_handler(CommandHandler('setproviderkey', set_provider_key)); application.add_handler(CommandHandler('adminusers', admin)); application.add_handler(CommandHandler('adminstats', adminstats)); application.add_handler(CommandHandler('adminaction', admin_action)); application.add_handler(CommandHandler('adminlimit', admin_limit)); application.add_handler(CommandHandler('adminpermission', admin_permission)); application.add_handler(CommandHandler('setotprate', set_otp_rate)); application.add_handler(CommandHandler('otprates', otp_rates_command)); application.add_handler(CommandHandler('tgzcontrol', tgz_control_command)); application.add_handler(CallbackQueryHandler(menu)); application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_menu)); application.add_error_handler(telegram_error_handler)
    return application

async def main():
    start_health_server()
    if not PROVIDER_BASE.endswith('/api/v1'):
        logger.warning('TGZ_API_BASE should end with /api/v1 (see API_Document). Current value: %s', PROVIDER_BASE)
    if provider_base_is_own_api():
        logger.warning(OWN_API_HINT)
    application = build_application()
    await application.initialize(); await application.start(); await application.updater.start_polling()
    try:
        while True: await asyncio.sleep(3600)
    finally: await application.updater.stop(); await application.stop(); await application.shutdown()

if __name__ == '__main__': asyncio.run(main())
