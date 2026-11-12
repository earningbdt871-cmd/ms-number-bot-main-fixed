import hashlib
import ipaddress
import logging
import os
import re
import time
from datetime import timedelta
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import and_, func, or_, select, update

from db import allocations, api_keys, api_permissions, app_settings, balance_transactions, engine, init_db, now, otp_rates, provider_settings, rate_limits, user_provider_keys, users, api_usage, webhook_deliveries
from secrets_store import decrypt

BASE = os.getenv('PROVIDER_API_BASE', '').rstrip('/')
MASTER = os.getenv('PROVIDER_API_KEY', '')
ADMIN_IDS = {int(x.strip()) for x in os.getenv('ADMIN_IDS', '').split(',') if x.strip().isdigit()}
logger = logging.getLogger('ms-number-api')
app = FastAPI(title='MS Number Bot Multi-User API', version='2.0.0')

DEFAULT_PERMISSIONS = {'me', 'balance', 'ranges', 'liveaccess', 'console', 'global-traffic', 'getnum', 'otp', 'success-otp', 'allocated', 'usage'}

@app.on_event('startup')
def startup():
    init_db()


def norm(value):
    return re.sub(r'\D+', '', str(value or ''))

def credit_otp(uid, allocation_id, service):
    """Credit one successful OTP exactly once (same rule as the Telegram bot)."""
    with engine.begin() as c:
        rate_row = None
        if service:
            rate_row = c.execute(select(otp_rates).where(otp_rates.c.service == str(service).strip(), otp_rates.c.enabled == True)).mappings().first()
        if rate_row:
            rate = int(rate_row['rate_paisa'])
        else:
            setting = c.execute(select(app_settings.c.value).where(app_settings.c.name == 'otp_reward_paisa')).first()
            rate = int(setting[0]) if setting else 40
        c.execute(select(allocations.c.id).where(allocations.c.id == allocation_id).with_for_update()).first()
        if c.execute(select(balance_transactions.c.id).where(balance_transactions.c.transaction_type == 'otp_credit', balance_transactions.c.allocation_id == allocation_id)).first():
            return 0
        c.execute(balance_transactions.insert().values(tg_id=uid, amount_paisa=rate, transaction_type='otp_credit', allocation_id=allocation_id, description=f'OTP credit ({service or "unknown service"})', created_at=now()))
        c.execute(update(users).where(users.c.tg_id == uid).values(balance_paisa=users.c.balance_paisa + rate))
        c.execute(update(allocations).where(allocations.c.id == allocation_id).values(credit_amount_paisa=rate, credited_at=now()))
    return rate

def hashkey(value):
    return hashlib.sha256(value.encode()).hexdigest()

def token_from(mauthapi=None, x_api_key=None, key=None):
    return mauthapi or x_api_key or key

def _user_by_key(token):
    digest = hashkey(token)
    with engine.begin() as c:
        keyrow = c.execute(select(api_keys).where(api_keys.c.key_hash == digest, api_keys.c.enabled == True, api_keys.c.revoked_at.is_(None))).mappings().first()
        if keyrow:
            user = c.execute(select(users).where(users.c.tg_id == keyrow['tg_id'])).mappings().first()
            return user, keyrow
        user = c.execute(select(users).where(users.c.api_hash == digest)).mappings().first()
        return user, None

def _permission_allowed(uid, permission):
    with engine.begin() as c:
        row = c.execute(select(api_permissions.c.enabled).where(api_permissions.c.tg_id == uid, api_permissions.c.permission == permission).order_by(api_permissions.c.id.desc())).first()
    return True if row is None else bool(row[0])

def _enforce_limit(uid, path):
    with engine.begin() as c:
        limit = c.execute(select(rate_limits).where(rate_limits.c.tg_id == uid)).mappings().first()
        if not limit:
            c.execute(rate_limits.insert().values(tg_id=uid, per_minute=60, per_day=5000, getnum_per_day=100, updated_at=now()))
            limit = {'per_minute': 60, 'per_day': 5000, 'getnum_per_day': 100}
        minute_count = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid, api_usage.c.created_at >= now() - timedelta(minutes=1))).scalar_one()
        day_count = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid, api_usage.c.created_at >= now() - timedelta(days=1))).scalar_one()
        if minute_count >= limit['per_minute'] or day_count >= limit['per_day']:
            raise HTTPException(429, 'API rate limit exceeded')
        if path == 'getnum':
            getnum_count = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid, api_usage.c.path.endswith('/getnum'), api_usage.c.created_at >= now() - timedelta(days=1))).scalar_one()
            if getnum_count >= limit['getnum_per_day']:
                raise HTTPException(429, 'Daily getnum limit exceeded')

def auth(mauthapi=None, x_api_key=None, key=None, permission=None):
    token = token_from(mauthapi, x_api_key, key)
    if not token:
        raise HTTPException(401, 'Missing API key')
    user, keyrow = _user_by_key(token)
    if not user:
        raise HTTPException(401, 'Invalid API key')
    if user['banned']:
        raise HTTPException(403, 'API access banned')
    if not user['enabled'] or (keyrow and not keyrow['enabled']):
        raise HTTPException(403, 'API access disabled')
    if permission and not _permission_allowed(user['tg_id'], permission):
        raise HTTPException(403, f'Permission denied: {permission}')
    _enforce_limit(user['tg_id'], permission or '')
    if keyrow:
        with engine.begin() as c:
            c.execute(update(api_keys).where(api_keys.c.id == keyrow['id']).values(last_used_at=now()))
    return {'user': user, 'key': keyrow}

def envcheck():
    if not BASE or not MASTER:
        raise HTTPException(503, 'Provider API is not configured')

async def provider(method, path, **kwargs):
    envcheck()
    uid = kwargs.pop('_uid', None)
    credential = MASTER
    if uid:
        with engine.begin() as c:
            own = c.execute(select(user_provider_keys).where(user_provider_keys.c.tg_id == uid, user_provider_keys.c.enabled == True)).mappings().first()
            setting = c.execute(select(provider_settings).where(provider_settings.c.name == 'provider_api_key')).mappings().first()
        if own:
            credential = decrypt(own['key_encrypted'])
        elif setting:
            credential = decrypt(setting['value_encrypted'])
    async with httpx.AsyncClient(timeout=38, follow_redirects=True) as client:
        response = await client.request(method, BASE + path, headers={'mauthapi': credential}, **kwargs)
    try:
        payload = response.json()
    except ValueError:
        raise HTTPException(502, 'Provider returned a non-JSON response')
    if response.status_code >= 400:
        logger.error('PROVIDER ERROR %s %s %s', path, response.status_code, response.text[:300])
        message = payload.get('message', 'Provider request failed') if isinstance(payload, dict) else 'Provider request failed'
        raise HTTPException(response.status_code, message)
    return payload

@app.middleware('http')
async def usage_logger(request: Request, call_next):
    started = time.perf_counter(); response = None; uid = None; key_id = None
    token = request.headers.get('mauthapi') or request.headers.get('x-api-key') or request.query_params.get('key')
    if token:
        try:
            user, keyrow = _user_by_key(token); uid = user['tg_id'] if user else None; key_id = keyrow['id'] if keyrow else None
        except Exception:
            pass
    try:
        response = await call_next(request)
        return response
    finally:
        if request.url.path.startswith('/api/v1'):
            try:
                with engine.begin() as c:
                    c.execute(api_usage.insert().values(tg_id=uid, api_key_id=key_id, method=request.method, path=request.url.path, status_code=response.status_code if response else 500, duration_ms=int((time.perf_counter() - started) * 1000), ip_address=request.client.host if request.client else None, user_agent=request.headers.get('user-agent'), created_at=now()))
            except Exception:
                pass

class NumberRequest(BaseModel):
    rid: str = Field(min_length=1, max_length=40)
    callback_url: AnyHttpUrl | None = None

class RateLimitRequest(BaseModel):
    per_minute: int = Field(ge=1, le=10000)
    per_day: int = Field(ge=1, le=1000000)
    getnum_per_day: int = Field(ge=1, le=100000)

class PermissionRequest(BaseModel):
    permission: str = Field(min_length=1, max_length=80)
    enabled: bool

def auth_args(mauthapi, x_api_key, key):
    return {'mauthapi': mauthapi, 'x_api_key': x_api_key, 'key': key}

@app.get('/')
def root(): return {'status': 'ok', 'service': 'ms-number-api'}

@app.head('/')
def root_head(): return None

@app.get('/health')
def health(): return {'status': 'ok'}

@app.head('/health')
def health_head(): return None

@app.get('/api/v1/me')
def me(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='me'); u = a['user']
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'user_id': u['tg_id'], 'enabled': bool(u['enabled']), 'banned': bool(u['banned']), 'key_prefix': a['key']['key_prefix'] if a['key'] else u['api_prefix']}, 'message': 'ok', 'rid': None}

@app.get('/api/v1/keys')
def keys(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='me')
    with engine.begin() as c:
        rows = c.execute(select(api_keys.c.id, api_keys.c.key_prefix, api_keys.c.label, api_keys.c.enabled, api_keys.c.created_at, api_keys.c.last_used_at, api_keys.c.revoked_at).where(api_keys.c.tg_id == a['user']['tg_id']).order_by(api_keys.c.id.desc())).mappings().all()
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'keys': [dict(r) for r in rows]}, 'message': 'ok', 'rid': None}

@app.get('/api/v1/usage')
def usage(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='usage'); uid = a['user']['tg_id']
    with engine.begin() as c:
        total = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid)).scalar_one()
        today = c.execute(select(func.count()).select_from(api_usage).where(api_usage.c.tg_id == uid, api_usage.c.created_at >= now() - timedelta(days=1))).scalar_one()
        rows = c.execute(select(api_usage.c.method, api_usage.c.path, api_usage.c.status_code, api_usage.c.duration_ms, api_usage.c.created_at).where(api_usage.c.tg_id == uid).order_by(api_usage.c.id.desc()).limit(100)).mappings().all()
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'total_requests': total, 'requests_today': today, 'recent': [dict(r) for r in rows]}, 'message': 'ok', 'rid': None}

async def proxy(permission, method, path, mauthapi, x_api_key, key, **kwargs):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission=permission)
    return await provider(method, path, _uid=a['user']['tg_id'], **kwargs)

@app.get('/api/v1/balance')
async def balance(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)): return await proxy('balance', 'GET', '/balance', mauthapi, x_api_key, key)
@app.get('/api/v1/ranges')
async def ranges(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)): return await proxy('ranges', 'GET', '/ranges', mauthapi, x_api_key, key)
@app.get('/api/v1/liveaccess')
async def liveaccess(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)): return await proxy('liveaccess', 'GET', '/liveaccess', mauthapi, x_api_key, key)
@app.get('/api/v1/console')
async def console(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)): return await proxy('console', 'GET', '/console', mauthapi, x_api_key, key)
@app.get('/api/v1/global-traffic')
async def global_traffic(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)): return await proxy('global-traffic', 'GET', '/global-traffic', mauthapi, x_api_key, key)

@app.post('/api/v1/getnum')
async def getnum(body: NumberRequest, mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='getnum'); payload = {'rid': body.rid}; callback = str(body.callback_url) if body.callback_url else None
    if callback:
        parsed = urlparse(callback)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname: raise HTTPException(400, 'callback_url must be a public http(s) URL')
        try:
            if ipaddress.ip_address(parsed.hostname).is_private: raise HTTPException(400, 'callback_url must not target a private IP')
        except ValueError: pass
        payload['callback_url'] = callback
    data = await provider('POST', '/getnum', _uid=a['user']['tg_id'], json=payload); details = data.get('data') or {}
    if data.get('meta', {}).get('code') == 200 and details:
        number = norm(details.get('no_plus_number') or details.get('full_number'))
        with engine.begin() as c:
            c.execute(allocations.insert().values(tg_id=a['user']['tg_id'], number=number, rid=body.rid, callback_url=callback, created_at=now(), status='allocated'))
    return data

@app.get('/api/v1/otp')
async def otp(number: str = Query(min_length=5, max_length=25), wait: int = Query(default=20, ge=0, le=30), mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='otp'); number = norm(number)
    with engine.begin() as c: owned = c.execute(select(allocations).where(allocations.c.tg_id == a['user']['tg_id'], allocations.c.number == number).order_by(allocations.c.id.desc())).mappings().first()
    if not owned: raise HTTPException(404, 'Number is not allocated to this API user')
    data = await provider('GET', '/otp', _uid=a['user']['tg_id'], params={'number': number, 'wait': wait}); result = data.get('data') or {}
    if result.get('otp'):
        with engine.begin() as c: c.execute(update(allocations).where(allocations.c.id == owned['id']).values(otp=str(result['otp']), service=result.get('service'), status='success'))
        try: credit_otp(a['user']['tg_id'], owned['id'], result.get('service'))
        except Exception: logger.exception('credit_otp failed')
    return data

@app.get('/api/v1/success-otp')
def success_otp(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='success-otp')
    with engine.begin() as c: rows = c.execute(select(allocations.c.number, allocations.c.otp, allocations.c.service, allocations.c.created_at).where(allocations.c.tg_id == a['user']['tg_id'], allocations.c.otp.is_not(None)).order_by(allocations.c.id.desc()).limit(50)).mappings().all()
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'cached': False, 'otps': [dict(r) for r in rows]}, 'message': 'ok', 'rid': None}

@app.get('/api/v1/allocated')
def allocated(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key), permission='allocated')
    with engine.begin() as c: rows = c.execute(select(allocations.c.number, allocations.c.rid, allocations.c.created_at, allocations.c.status).where(allocations.c.tg_id == a['user']['tg_id']).order_by(allocations.c.id.desc()).limit(100)).mappings().all()
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'numbers': [dict(r) for r in rows]}, 'message': 'ok', 'rid': None}

@app.get('/api/v1/admin/stats')
def admin_stats(mauthapi: str | None = Header(default=None), x_api_key: str | None = Header(default=None, alias='X-API-Key'), key: str | None = Query(default=None)):
    a = auth(**auth_args(mauthapi, x_api_key, key))
    if a['user']['tg_id'] not in ADMIN_IDS: raise HTTPException(403, 'Admin only')
    with engine.begin() as c:
        total = c.execute(select(func.count()).select_from(users)).scalar_one(); active = c.execute(select(func.count()).select_from(users).where(users.c.enabled == True, users.c.banned == False)).scalar_one(); disabled = c.execute(select(func.count()).select_from(users).where(users.c.enabled == False)).scalar_one(); requests = c.execute(select(func.count()).select_from(api_usage)).scalar_one()
    return {'meta': {'code': 200, 'status': 'ok'}, 'data': {'total_users': total, 'active_users': active, 'disabled_users': disabled, 'total_requests': requests}, 'message': 'ok', 'rid': None}
    
