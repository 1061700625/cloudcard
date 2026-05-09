"""
云端服务器主程序
FastAPI 实现卡密验证系统的后端服务
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import json, base64, time, csv, io

from config import (
    API_HOST, API_PORT, API_DEBUG,
    ADMIN_API_KEY, DEFAULT_KEY,
    IP_WHITELIST_ENABLED, IP_WHITELIST,
)
from database import Database
from crypto import CryptoManager


app = FastAPI(title="云控卡密验证系统", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/admin")
async def admin_page():
    return FileResponse("static/admin.html", media_type="text/html")

db = Database()
crypto = CryptoManager(DEFAULT_KEY)


# ============ Pydantic 模型 ============

class GenerateCardRequest(BaseModel):
    expire_minutes: int = 43200  # 默认30天 = 43200 分钟
    count: int = 1
    admin_key: str

class VerifyCardRequest(BaseModel):
    ciphertext: str
    iv: str
    signature: str

class QueryCardRequest(BaseModel):
    card_key: str
    admin_key: str

class ToggleCardRequest(BaseModel):
    card_key: str
    status: int
    admin_key: str

class DeleteCardRequest(BaseModel):
    card_key: str
    admin_key: str

class ListCardsRequest(BaseModel):
    status: Optional[int] = None
    limit: int = 100
    offset: int = 0
    admin_key: str

class ImportCardItem(BaseModel):
    card_key: str
    expire_minutes: int = 43200

class ImportCardsRequest(BaseModel):
    cards: List[ImportCardItem]
    admin_key: str

class WhitelistRequest(BaseModel):
    ip_cidr: str
    description: str = ''
    admin_key: str

class HeartbeatRequest(BaseModel):
    ciphertext: str
    iv: str
    signature: str

class OfflineRequest(BaseModel):
    ciphertext: str
    iv: str
    signature: str


# ============ 依赖 ============

async def verify_admin_key(request: Request):
    key = request.headers.get('X-Admin-Key')
    if not key:
        try:
            body = await request.json()
            key = body.get('admin_key')
        except Exception:
            raise HTTPException(status_code=403, detail="缺少管理员凭证")
    if key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="管理员权限验证失败")
    return key

def get_client_ip(request: Request) -> str:
    fwd = request.headers.get('X-Forwarded-For')
    if fwd:
        return fwd.split(',')[0].strip()
    real = request.headers.get('X-Real-IP')
    if real:
        return real
    return request.client.host


# ============ 路由 ============

@app.get("/")
def root():
    return {
        "message": "云控卡密验证系统API",
        "version": "2.0.0",
        "endpoints": {
            "生成卡密": "POST /api/card/generate",
            "验证卡密": "POST /api/card/verify",
            "查询卡密": "POST /api/card/query",
            "禁用/启用": "POST /api/card/toggle",
            "删除卡密": "POST /api/card/delete",
            "列出卡密": "POST /api/card/list",
            "导出卡密": "POST /api/card/export",
            "导入卡密": "POST /api/card/import",
            "统计信息": "GET /api/stats",
            "审计日志": "GET /api/admin/logs",
            "在线设备": "GET /api/client/online-devices",
            "白名单列表": "GET /api/config/whitelist/list",
            "添加白名单": "POST /api/config/whitelist/add",
            "删除白名单": "POST /api/config/whitelist/remove"
        }
    }


@app.post("/api/card/generate")
async def generate_card(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    expire_minutes = body.get('expire_minutes', 43200)
    count = body.get('count', 1)
    if expire_minutes <= 0:
        raise HTTPException(status_code=400, detail="过期分钟数必须大于0")
    if count <= 0 or count > 100:
        raise HTTPException(status_code=400, detail="生成数量必须在1-100之间")
    keys = db.create_cards(expire_minutes, count)
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "generate_cards", f"生成{len(keys)}张卡密，有效期{expire_minutes}分钟", ip)
    return {"success": True, "message": f"成功生成{len(keys)}个卡密", "cards": keys}


@app.post("/api/card/verify")
async def verify_card(request: Request, req: VerifyCardRequest):
    try:
        if IP_WHITELIST_ENABLED:
            client_ip = get_client_ip(request)
            if not db.check_ip_whitelisted(client_ip):
                raise HTTPException(status_code=403, detail="IP不在白名单内")

        data_to_verify = req.ciphertext + req.iv
        if not crypto.verify_hmac(data_to_verify, req.signature):
            raise HTTPException(status_code=400, detail="签名验证失败")

        decrypted = crypto.decrypt(req.ciphertext, req.iv)
        data = json.loads(decrypted)
        card_key = data.get('card_key')
        device_sn = data.get('device_sn')
        ip_address = data.get('ip_address')
        timestamp = data.get('timestamp', 0)
        if not all([card_key, device_sn, ip_address]):
            raise HTTPException(status_code=400, detail="缺少必要参数")
        now = int(time.time())
        if abs(now - timestamp) > 300:
            raise HTTPException(status_code=400, detail="请求已过期，请检查系统时间")

        result = db.verify_card(card_key, device_sn, ip_address)

        resp_data = json.dumps(result)
        enc = crypto.encrypt(resp_data)
        sig = crypto.generate_hmac(enc['ciphertext'] + enc['iv'])
        return {"ciphertext": enc['ciphertext'], "iv": enc['iv'], "signature": sig}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"验证处理失败: {str(e)}")


@app.post("/api/card/query")
async def query_card(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    card_key = body.get('card_key', '')
    card = db.get_card(card_key)
    if not card:
        raise HTTPException(status_code=404, detail="卡密不存在")
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "query_card", f"查询卡密: {card_key}", ip)
    return {"success": True, "card": card}


@app.post("/api/card/toggle")
async def toggle_card(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    card_key = body.get('card_key', '')
    status = body.get('status', 0)
    if status not in [0, 1, 2, 3]:
        raise HTTPException(status_code=400, detail="无效的状态值")
    ok = db.update_card_status(card_key, status)
    if not ok:
        raise HTTPException(status_code=404, detail="卡密不存在")
    names = {0: "未使用", 1: "已激活", 2: "已禁用", 3: "已过期"}
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "toggle_card", f"卡密{card_key}状态变更为: {names[status]}", ip)
    return {"success": True, "message": f"卡密状态已更新为：{names[status]}"}


@app.post("/api/card/delete")
async def delete_card(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    card_key = body.get('card_key', '')
    ok = db.delete_card(card_key)
    if not ok:
        raise HTTPException(status_code=404, detail="卡密不存在")
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "delete_card", f"删除卡密: {card_key}", ip)
    return {"success": True, "message": "卡密已删除"}


@app.post("/api/card/list")
async def list_cards(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    status = body.get('status')
    limit = body.get('limit', 100)
    offset = body.get('offset', 0)
    if limit <= 0 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit必须在1-1000之间")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset不能小于0")
    cards = db.list_cards(status, limit, offset)
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "list_cards", f"列出卡密，过滤: {status}，返回{len(cards)}条", ip)
    return {"success": True, "count": len(cards), "cards": cards}


@app.post("/api/card/export")
async def export_cards(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    status = body.get('status')
    limit = body.get('limit', 1000)
    cards = db.list_cards(status, limit, 0)
    if not cards:
        raise HTTPException(status_code=404, detail="没有可导出的卡密")
    output = io.StringIO()
    fieldnames = ['card_key', 'status', 'expire_time', 'device_sn', 'created_at', 'activated_at']
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    status_names = {0: '未使用', 1: '已激活', 2: '已禁用', 3: '已过期'}
    for c in cards:
        row = {k: c.get(k, '') for k in fieldnames}
        row['status'] = status_names.get(row['status'], str(row['status']))
        if row['expire_time']:
            row['expire_time'] = datetime.fromtimestamp(row['expire_time']).strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow(row)
    csv_content = output.getvalue()
    output.close()
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "export_cards", f"导出{len(cards)}张卡密", ip)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cards_export.csv"}
    )


@app.post("/api/card/import")
async def import_cards(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    cards = body.get('cards', [])
    if not cards:
        raise HTTPException(status_code=400, detail="没有要导入的卡密")
    if len(cards) > 500:
        raise HTTPException(status_code=400, detail="单次导入不能超过500条")
    imported = 0
    failed = 0
    failed_keys = []
    for item in cards:
        ck = item.get('card_key', '')
        ed = item.get('expire_minutes', 43200)
        if not ck.startswith('CARD-') or len(ck) < 10:
            failed += 1
            failed_keys.append(ck)
            continue
        expire_time = int((datetime.now() + timedelta(days=ed)).timestamp())
        conn = db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO cards (card_key, expire_time) VALUES (?, ?)', (ck, expire_time))
            conn.commit()
            imported += 1
        except sqlite3.IntegrityError:
            failed += 1
            failed_keys.append(ck)
        finally:
            conn.close()
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "import_cards", f"导入: 成功{imported}条，失败{failed}条", ip)
    return {"success": True, "imported": imported, "failed": failed,
            "failed_keys": failed_keys,
            "message": f"导入完成：成功{imported}条，失败{failed}条"}


@app.get("/api/stats")
async def get_stats(admin_key: str = Query(...)):
    if admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="管理员权限验证失败")
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT status, COUNT(*) as cnt FROM cards GROUP BY status')
    cs = {r['status']: r['cnt'] for r in cursor.fetchall()}
    cursor.execute('SELECT COUNT(*) as cnt FROM devices')
    dc = cursor.fetchone()['cnt']
    cursor.execute('SELECT result, COUNT(*) as cnt FROM verify_logs GROUP BY result')
    vs = {r['result']: r['cnt'] for r in cursor.fetchall()}
    cursor.execute('SELECT COUNT(*) as cnt FROM devices WHERE is_online = 1')
    oc = cursor.fetchone()['cnt']
    conn.close()
    return {"success": True, "stats": {
        "cards": {"total": sum(cs.values()), "unused": cs.get(0,0), "activated": cs.get(1,0),
                   "disabled": cs.get(2,0), "expired": cs.get(3,0)},
        "devices": {"total": dc, "online": oc},
        "verifies": {"success": vs.get(1,0), "failed": vs.get(0,0)}
    }}


@app.get("/api/admin/logs")
async def get_admin_logs(admin_key: str = Query(...), limit: int = Query(200)):
    if admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="管理员权限验证失败")
    logs = db.get_admin_logs(min(limit, 500))
    return {"success": True, "count": len(logs), "logs": logs}


@app.get("/api/config/whitelist/list")
async def list_whitelist(admin_key: str = Query(...)):
    if admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="管理员权限验证失败")
    return {"success": True, "count": len(db.list_ip_whitelist()),
            "whitelist": db.list_ip_whitelist(), "enabled": IP_WHITELIST_ENABLED}


@app.post("/api/config/whitelist/add")
async def add_whitelist(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    ip_cidr = body.get('ip_cidr', '')
    desc = body.get('description', '')
    ok = db.add_ip_whitelist(ip_cidr, desc)
    if not ok:
        raise HTTPException(status_code=400, detail="添加失败，CIDR格式错误或已存在")
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "add_whitelist", f"添加白名单: {ip_cidr}", ip)
    return {"success": True, "message": f"已添加白名单: {ip_cidr}"}


@app.post("/api/config/whitelist/remove")
async def remove_whitelist(request: Request, admin_key: str = Depends(verify_admin_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的JSON请求体")
    ip_cidr = body.get('ip_cidr', '')
    ok = db.remove_ip_whitelist(ip_cidr)
    if not ok:
        raise HTTPException(status_code=404, detail="白名单条目不存在")
    ip = get_client_ip(request)
    db.log_admin_action(admin_key, "remove_whitelist", f"删除白名单: {ip_cidr}", ip)
    return {"success": True, "message": f"已删除白名单: {ip_cidr}"}


# ============ 心跳接口 ============

@app.post("/api/client/heartbeat")
async def client_heartbeat(req: HeartbeatRequest):
    try:
        data_to_verify = req.ciphertext + req.iv
        if not crypto.verify_hmac(data_to_verify, req.signature):
            raise HTTPException(status_code=400, detail="签名验证失败")

        decrypted = crypto.decrypt(req.ciphertext, req.iv)
        data = json.loads(decrypted)
        device_sn = data.get('device_sn')
        ip_address = data.get('ip_address', '')
        timestamp = data.get('timestamp', 0)
        if not device_sn:
            raise HTTPException(status_code=400, detail="缺少设备序列号")
        now = int(time.time())
        if abs(now - timestamp) > 300:
            raise HTTPException(status_code=400, detail="请求已过期")

        db.update_heartbeat(device_sn, ip_address)
        db.mark_stale_devices_offline(120)
        info = db.get_device_heartbeat_info(device_sn)
        resp = {"success": True, "message": "心跳更新成功",
                "remaining_seconds": info["remaining_seconds"],
                "expire_minutes": info["expire_minutes"]}
        resp_data = json.dumps(resp)
        enc = crypto.encrypt(resp_data)
        sig = crypto.generate_hmac(enc['ciphertext'] + enc['iv'])
        return {"ciphertext": enc['ciphertext'], "iv": enc['iv'], "signature": sig}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"心跳处理失败: {str(e)}")


@app.post("/api/client/offline")
async def client_offline(req: OfflineRequest):
    try:
        data_to_verify = req.ciphertext + req.iv
        if not crypto.verify_hmac(data_to_verify, req.signature):
            raise HTTPException(status_code=400, detail="签名验证失败")

        decrypted = crypto.decrypt(req.ciphertext, req.iv)
        data = json.loads(decrypted)
        device_sn = data.get('device_sn')
        if not device_sn:
            raise HTTPException(status_code=400, detail="缺少设备序列号")

        db.set_device_offline(device_sn)
        return {"success": True, "message": "已下线"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"下线处理失败: {str(e)}")


@app.get("/api/client/online-devices")
async def get_online_devices(admin_key: str = Query(...)):
    if admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="管理员权限验证失败")
    db.mark_stale_devices_offline(120)
    devices = db.get_online_devices()
    return {"success": True, "count": len(devices), "devices": devices}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=API_DEBUG)
