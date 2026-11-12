import os
from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, inspect, select, text

DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql+psycopg://', 1)
elif DATABASE_URL and DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgresql+psycopg://', 1)

URL = DATABASE_URL or f"sqlite:///{os.getenv('DB_PATH', 'data.sqlite3')}"
engine = create_engine(URL, pool_pre_ping=True, future=True)
metadata = MetaData()

users = Table('users', metadata,
    Column('tg_id', BigInteger, primary_key=True), Column('api_hash', String(128)), Column('api_prefix', String(32)),
    Column('username', String(128)), Column('display_name', String(255)),
    Column('enabled', Boolean, nullable=False, default=True), Column('banned', Boolean, nullable=False, default=False),
    Column('balance_paisa', Integer, nullable=False, default=0),
    Column('created_at', DateTime(timezone=True), nullable=False),
)
allocations = Table('allocations', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger, nullable=False),
    Column('number', String(32), nullable=False), Column('rid', String(64), nullable=False), Column('callback_url', Text),
    Column('created_at', DateTime(timezone=True), nullable=False), Column('status', String(24), nullable=False, default='allocated'),
    Column('otp', String(32)), Column('service', String(128)), Column('credit_amount_paisa', Integer), Column('credited_at', DateTime(timezone=True)),
)
api_keys = Table('api_keys', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger, nullable=False),
    Column('key_hash', String(128), nullable=False, unique=True), Column('key_prefix', String(32), nullable=False),
    Column('label', String(80), nullable=False, default='default'), Column('enabled', Boolean, nullable=False, default=True),
    Column('created_at', DateTime(timezone=True), nullable=False), Column('last_used_at', DateTime(timezone=True)),
    Column('revoked_at', DateTime(timezone=True)), Column('expires_at', DateTime(timezone=True)),
)
api_usage = Table('api_usage', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger), Column('api_key_id', Integer),
    Column('method', String(12), nullable=False), Column('path', String(255), nullable=False), Column('status_code', Integer),
    Column('duration_ms', Integer), Column('ip_address', String(64)), Column('user_agent', Text), Column('created_at', DateTime(timezone=True), nullable=False),
)
rate_limits = Table('rate_limits', metadata,
    Column('tg_id', BigInteger, primary_key=True), Column('per_minute', Integer, nullable=False, default=60),
    Column('per_day', Integer, nullable=False, default=5000), Column('getnum_per_day', Integer, nullable=False, default=100), Column('updated_at', DateTime(timezone=True), nullable=False),
)
api_permissions = Table('api_permissions', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger, nullable=False),
    Column('permission', String(80), nullable=False), Column('enabled', Boolean, nullable=False, default=True),
    Column('updated_at', DateTime(timezone=True), nullable=False),
)
webhook_deliveries = Table('webhook_deliveries', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger), Column('allocation_id', Integer),
    Column('callback_url', Text), Column('event', String(40), nullable=False), Column('status_code', Integer),
    Column('attempts', Integer, nullable=False, default=0), Column('created_at', DateTime(timezone=True), nullable=False),
)
provider_settings = Table('provider_settings', metadata,
    Column('name', String(80), primary_key=True), Column('value_encrypted', Text, nullable=False),
    Column('updated_by', BigInteger), Column('updated_at', DateTime(timezone=True), nullable=False),
)
user_provider_keys = Table('user_provider_keys', metadata,
    Column('tg_id', BigInteger, primary_key=True), Column('key_encrypted', Text, nullable=False),
    Column('provider', String(32), nullable=False, default='tgz'), Column('enabled', Boolean, nullable=False, default=True),
    Column('updated_at', DateTime(timezone=True), nullable=False),
)

otp_rates = Table('otp_rates', metadata,
    Column('service', String(128), primary_key=True), Column('rate_paisa', Integer, nullable=False),
    Column('enabled', Boolean, nullable=False, default=True), Column('updated_by', BigInteger),
    Column('updated_at', DateTime(timezone=True), nullable=False),
)
balance_transactions = Table('balance_transactions', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True), Column('tg_id', BigInteger, nullable=False),
    Column('amount_paisa', Integer, nullable=False), Column('transaction_type', String(40), nullable=False), Column('withdrawal_id', String(40)),
    Column('allocation_id', Integer), Column('description', Text), Column('created_at', DateTime(timezone=True), nullable=False),
)
app_settings = Table('app_settings', metadata,
    Column('name', String(80), primary_key=True), Column('value', Text, nullable=False),
    Column('updated_by', BigInteger), Column('updated_at', DateTime(timezone=True), nullable=False),
)

withdrawals = Table('withdrawals', metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('withdrawal_id', String(40), nullable=False, unique=True),
    Column('tg_id', BigInteger, nullable=False), Column('username', String(128)),
    Column('amount_paisa', Integer, nullable=False), Column('method', String(64), nullable=False),
    Column('payment_info_encrypted', Text, nullable=False), Column('status', String(16), nullable=False, default='pending'),
    Column('rejection_reason', Text), Column('requested_at', DateTime(timezone=True), nullable=False),
    Column('approved_at', DateTime(timezone=True)), Column('approved_by', BigInteger),
    Column('rejected_at', DateTime(timezone=True)), Column('rejected_by', BigInteger),
    Column('paid_at', DateTime(timezone=True)), Column('paid_by', BigInteger),
)

def now():
    return datetime.now(timezone.utc)

def _add_missing_columns(connection, table_name, columns):
    existing = {c['name'] for c in inspect(connection).get_columns(table_name)}
    for name, ddl in columns.items():
        if name not in existing:
            connection.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {name} {ddl}'))

def init_db():
    metadata.create_all(engine)
    with engine.begin() as c:
        # Do not ALTER existing PostgreSQL columns on every restart. Those
        # operations can wait for table locks on Render and stall startup.
        # All declared Telegram-ID columns already use BigInteger; older
        # deployments should be migrated once with a separate SQL migration.
        _add_missing_columns(c, 'users', {'api_hash': 'VARCHAR(128)', 'api_prefix': 'VARCHAR(32)', 'username': 'VARCHAR(128)', 'display_name': 'VARCHAR(255)', 'enabled': 'BOOLEAN', 'banned': 'BOOLEAN', 'balance_paisa': 'INTEGER DEFAULT 0', 'created_at': 'TIMESTAMP WITH TIME ZONE'})
        _add_missing_columns(c, 'allocations', {'callback_url': 'TEXT', 'status': 'VARCHAR(24)', 'otp': 'VARCHAR(32)', 'service': 'VARCHAR(128)', 'credit_amount_paisa': 'INTEGER', 'credited_at': 'TIMESTAMP WITH TIME ZONE'})
        _add_missing_columns(c, 'balance_transactions', {'withdrawal_id': 'VARCHAR(40)'})
        c.execute(text("UPDATE users SET enabled=TRUE WHERE enabled IS NULL"))
        c.execute(text("UPDATE users SET banned=FALSE WHERE banned IS NULL"))
        c.execute(text("UPDATE users SET balance_paisa=0 WHERE balance_paisa IS NULL"))
        c.execute(text("UPDATE allocations SET status='allocated' WHERE status IS NULL"))
        if not c.execute(select(otp_rates.c.service).where(otp_rates.c.service == '__default__')).first():
            c.execute(otp_rates.insert().values(service='__default__', rate_paisa=40, enabled=True, updated_at=now()))
        defaults = {
            'withdraw_enabled': 'on', 'min_withdraw_paisa': '5000', 'otp_reward_paisa': '40',
            'refer_reward_paisa': '20', 'cooldown_seconds': '10', 'num_per_request': '3',
            'num_per_share': '1', 'support_link_enabled': 'on', 'withdraw_methods': 'bKash,Nagad',
            'withdraw_group_enabled': 'on', 'api_url': 'AUTO',
        }
        for name, value in defaults.items():
            if not c.execute(select(app_settings.c.name).where(app_settings.c.name == name)).first():
                c.execute(app_settings.insert().values(name=name, value=value, updated_at=now()))
