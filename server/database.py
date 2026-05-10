"""
数据库操作模块
包含：卡密管理、设备心跳、审计日志、IP白名单
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sqlite3, time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from config import DATABASE_PATH, CARD_KEY_PREFIX, CARD_KEY_SEPARATOR, CARD_KEY_LENGTH, VERIFY_INTERVAL_SECONDS


class Database:
    """数据库操作类"""

    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """初始化数据库表（含迁移）"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_key TEXT UNIQUE NOT NULL,
            expire_time INTEGER NOT NULL,
            status INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            activated_at TIMESTAMP,
            device_sn TEXT,
            UNIQUE(card_key)
        )
        ''')

        # 迁移：添加 expire_minutes 字段
        try:
            cursor.execute('ALTER TABLE cards ADD COLUMN expire_minutes INTEGER DEFAULT 43200')
        except sqlite3.OperationalError:
            pass

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_sn TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            last_verify_time TIMESTAMP,
            card_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_key) REFERENCES cards (card_key)
        )
        ''')

        # 迁移：添加 last_heartbeat 字段
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN last_heartbeat TIMESTAMP')
        except sqlite3.OperationalError:
            pass

        # 迁移：添加 is_online 字段
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN is_online INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS verify_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_key TEXT NOT NULL,
            device_sn TEXT NOT NULL,
            ip_address TEXT,
            verify_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result INTEGER,
            message TEXT,
            FOREIGN KEY (card_key) REFERENCES cards (card_key)
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_key_hash TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_cidr TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        conn.commit()
        conn.close()

    def generate_card_key(self) -> str:
        import secrets
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        random_part = ''.join(secrets.choice(chars) for _ in range(CARD_KEY_LENGTH))
        parts = [random_part[i:i+4] for i in range(0, len(random_part), 4)]
        return CARD_KEY_PREFIX + CARD_KEY_SEPARATOR + CARD_KEY_SEPARATOR.join(parts)

    def create_cards(self, expire_minutes: int, count: int = 1) -> List[str]:
        conn = self.get_connection()
        cursor = conn.cursor()
        expire_time = int((datetime.now() + timedelta(minutes=expire_minutes)).timestamp())
        card_keys = []
        for _ in range(count):
            while True:
                card_key = self.generate_card_key()
                try:
                    cursor.execute('INSERT INTO cards (card_key, expire_time, expire_minutes) VALUES (?, ?, ?)',
                                 (card_key, expire_time, expire_minutes))
                    card_keys.append(card_key)
                    break
                except sqlite3.IntegrityError:
                    continue
        conn.commit()
        conn.close()
        return card_keys

    def get_card(self, card_key: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def verify_card(self, card_key: str, device_sn: str, ip_address: str) -> Dict[str, Any]:
        conn = self.get_connection()
        cursor = conn.cursor()

        # 频率限制
        cursor.execute('SELECT last_verify_time FROM devices WHERE device_sn = ? AND card_key = ?',
                     (device_sn, card_key))
        device_row = cursor.fetchone()
        now = int(datetime.now().timestamp())
        if device_row and device_row['last_verify_time']:
            try:
                last = int(datetime.strptime(device_row['last_verify_time'], '%Y-%m-%d %H:%M:%S').timestamp())
                if now - last < VERIFY_INTERVAL_SECONDS:
                    remaining = VERIFY_INTERVAL_SECONDS - (now - last)
                    conn.close()
                    return {'success': False, 'message': f'验证频率限制，请{remaining}秒后再试',
                            'remaining_seconds': remaining, 'rate_limited': True}
            except Exception:
                pass

        cursor.execute('SELECT * FROM cards WHERE card_key = ?', (card_key,))
        card = cursor.fetchone()
        result = {'success': False, 'message': '', 'remaining_seconds': 0}

        def log(result_code, msg):
            cursor.execute(
                'INSERT INTO verify_logs (card_key, device_sn, ip_address, result, message) VALUES (?, ?, ?, ?, ?)',
                (card_key, device_sn, ip_address, result_code, msg))

        if not card:
            result['message'] = '卡密不存在'
            log(0, result['message'])
            conn.commit()
            conn.close()
            return result

        card = dict(card)
        if card['status'] == 2:
            result['message'] = '卡密已被禁用'
            log(0, result['message'])
            conn.commit()
            conn.close()
            return result

        if now > card['expire_time']:
            cursor.execute('UPDATE cards SET status = 3 WHERE card_key = ?', (card_key,))
            result['message'] = '卡密已过期'
            log(0, result['message'])
            conn.commit()
            conn.close()
            return result

        if card['status'] == 0:
            # 激活时根据 expire_minutes 重新计算过期时间
            expire_minutes = card.get('expire_minutes') or 43200
            new_expire_time = int((datetime.now() + timedelta(minutes=expire_minutes)).timestamp())
            cursor.execute(
                '''INSERT OR REPLACE INTO devices (device_sn, ip_address, last_verify_time, card_key)
                   VALUES (?, ?, CURRENT_TIMESTAMP, ?)''',
                (device_sn, ip_address, card_key))
            cursor.execute(
                '''UPDATE cards SET status = 1, activated_at = CURRENT_TIMESTAMP, device_sn = ?,
                   expire_time = ?
                   WHERE card_key = ?''',
                (device_sn, new_expire_time, card_key))
            result = {'success': True, 'message': '激活成功',
                       'remaining_seconds': expire_minutes * 60,
                       'expire_minutes': expire_minutes}
            log(1, result['message'])

        elif card['status'] == 1:
            if card['device_sn'] == device_sn:
                cursor.execute(
                    'UPDATE devices SET last_verify_time = CURRENT_TIMESTAMP, ip_address = ? WHERE device_sn = ?',
                    (ip_address, device_sn))
                expire_minutes = card.get('expire_minutes') or 43200
                result = {'success': True, 'message': '验证成功',
                           'remaining_seconds': card['expire_time'] - now,
                           'expire_minutes': expire_minutes}
                log(1, result['message'])
            else:
                result['message'] = '卡密已绑定其他设备'
                log(0, result['message'])

        conn.commit()
        conn.close()
        return result

    def update_card_status(self, card_key: str, status: int) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE cards SET status = ? WHERE card_key = ?', (status, card_key))
        ok = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return ok

    def list_cards(self, status=None, limit=100, offset=0) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        if status is not None:
            cursor.execute('SELECT * FROM cards WHERE status = ? ORDER BY id DESC LIMIT ? OFFSET ?',
                         (status, limit, offset))
        else:
            cursor.execute('SELECT * FROM cards ORDER BY id DESC LIMIT ? OFFSET ?',
                         (limit, offset))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_card(self, card_key: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM devices WHERE card_key = ?', (card_key,))
        cursor.execute('DELETE FROM verify_logs WHERE card_key = ?', (card_key,))
        cursor.execute('DELETE FROM cards WHERE card_key = ?', (card_key,))
        ok = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return ok

    # ============ 心跳相关 ============

    def update_heartbeat(self, device_sn: str, ip_address: str) -> bool:
        """更新心跳时间，标记在线"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''UPDATE devices
               SET last_heartbeat = CURRENT_TIMESTAMP,
                   is_online = 1,
                   ip_address = ?
               WHERE device_sn = ?''',
            (ip_address, device_sn)
        )
        ok = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return ok

    def set_device_offline(self, device_sn: str) -> bool:
        """标记设备离线"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE devices SET is_online = 0 WHERE device_sn = ?', (device_sn,))
        ok = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return ok

    def get_device_heartbeat_info(self, device_sn: str) -> dict:
        """
        查询设备心跳相关信息：
        - remaining_seconds: 剩余秒数
        - expire_minutes: 卡密总有效分钟数（用于客户端显示有效期）
        设备未绑定卡密、卡密不存在或已过期时 remaining_seconds 返回 0
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT c.expire_time, c.expire_minutes
                 FROM devices d
                 JOIN cards c ON c.card_key = d.card_key
                WHERE d.device_sn = ? AND d.is_online = 1
                LIMIT 1''',
            (device_sn,)
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return {"remaining_seconds": 0, "expire_minutes": 0}
        now_ts = int(time.time())
        from datetime import datetime
        now_dt = int(datetime.now().timestamp())
        remaining = max(0, row['expire_time'] - now_ts)
        expire_minutes = row['expire_minutes'] or 0
        print(f"[DB DEBUG] expire_time={row['expire_time']}, now_ts={now_ts}, now_dt={now_dt}, remaining={remaining}", flush=True)
        return {"remaining_seconds": remaining, "expire_minutes": expire_minutes}
        return {"remaining_seconds": remaining, "expire_minutes": expire_minutes}

    def mark_stale_devices_offline(self, timeout_seconds: int = 120) -> int:
        """
        将超过 timeout_seconds 未心跳的设备标记为离线
        SQL 逻辑：last_heartbeat 距今超过 timeout_seconds 秒则视为离线
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        # 正确逻辑：如果 last_heartbeat 加上 timeout_seconds 仍小于当前时间，说明已超时
        cursor.execute(
            '''UPDATE devices
               SET is_online = 0
               WHERE is_online = 1
                 AND (last_heartbeat IS NULL
                      OR datetime('now') > datetime(last_heartbeat, ?))''',
            (f'{timeout_seconds} seconds',)
        )
        count = cursor.rowcount
        conn.commit()
        conn.close()
        return count

    def get_online_devices(self) -> List[Dict[str, Any]]:
        """获取所有在线设备（先清理超时设备）"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''UPDATE devices
               SET is_online = 0
               WHERE is_online = 1
                 AND (last_heartbeat IS NULL
                      OR datetime('now') > datetime(last_heartbeat, '120 seconds'))'''
        )
        cursor.execute(
            '''SELECT d.*, c.card_key, c.status as card_status, c.expire_time
               FROM devices d
               LEFT JOIN cards c ON d.card_key = c.card_key
               WHERE d.is_online = 1
               ORDER BY d.last_heartbeat DESC'''
        )
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    # ============ 审计日志 ============

    def log_admin_action(self, admin_key: str, action: str, detail: str, ip_address: str):
        import hashlib
        conn = self.get_connection()
        cursor = conn.cursor()
        key_hash = hashlib.sha256(admin_key.encode()).hexdigest()[:8]
        cursor.execute(
            'INSERT INTO admin_logs (admin_key_hash, action, detail, ip_address) VALUES (?, ?, ?, ?)',
            (key_hash, action, detail, ip_address))
        conn.commit()
        conn.close()

    def get_admin_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    # ============ IP白名单 ============

    def check_ip_whitelisted(self, ip_address: str) -> bool:
        import ipaddress
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT ip_cidr FROM ip_whitelist')
        rows = cursor.fetchall()
        conn.close()
        if not rows:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for row in rows:
                if ip_obj in ipaddress.ip_network(row['ip_cidr'], strict=False):
                    return True
        except ValueError:
            return False
        return False

    def add_ip_whitelist(self, ip_cidr: str, description: str = '') -> bool:
        import ipaddress
        try:
            ipaddress.ip_network(ip_cidr, strict=False)
        except ValueError:
            return False
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO ip_whitelist (ip_cidr, description) VALUES (?, ?)',
                         (ip_cidr, description))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False

    def remove_ip_whitelist(self, ip_cidr: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM ip_whitelist WHERE ip_cidr = ?', (ip_cidr,))
        ok = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return ok

    def list_ip_whitelist(self) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ip_whitelist ORDER BY created_at DESC')
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result
