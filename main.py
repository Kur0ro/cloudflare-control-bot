import asyncio
import aiohttp
import datetime
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.filters import Command
from aiogram.exceptions import TelegramNetworkError, TelegramBadRequest

# ===== Logging Setup =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ===== Configuration =====
BOT_TOKEN = "токен"
CLOUDFLARE_ZONE_ID = "айди домена"
CLOUDFLARE_API_KEY = "ключ"
CLOUDFLARE_EMAIL = "почта"
ALLOWED_USERS = [124555, 12354]

bot = Bot(BOT_TOKEN)
dp = Dispatcher()

# ===== Keyboards =====
main_kb = ReplyKeyboardMarkup(
    keyboard=[
        [
            KeyboardButton(text="🛡️ Включить защиту"),
            KeyboardButton(text="⚪ Выключить защиту")
        ],
        [
            KeyboardButton(text="👁️ Показать текущий уровень"),
            KeyboardButton(text="📊 Показать аналитику")
        ],
        [
            KeyboardButton(text="🔒 Anti-DDoS")
        ]
    ],
    resize_keyboard=True
)

level_kb = InlineKeyboardMarkup(
    inline_keyboard=[
        [InlineKeyboardButton(text="🟢 Off", callback_data="essentially_off")],
        [InlineKeyboardButton(text="🟡 Low", callback_data="low")],
        [InlineKeyboardButton(text="🟠 Medium", callback_data="medium")],
        [InlineKeyboardButton(text="🔴 High", callback_data="high")],
        [InlineKeyboardButton(text="🚨 Under Attack", callback_data="under_attack")]
    ]
)

anti_ddos_kb = InlineKeyboardMarkup(
    inline_keyboard=[
        [InlineKeyboardButton(text="🔛 Включить BFM", callback_data="bfm_on"),
         InlineKeyboardButton(text="🛑 Выключить BFM", callback_data="bfm_off")],
        [InlineKeyboardButton(text="🔛 Включить BIC", callback_data="bic_on"),
         InlineKeyboardButton(text="🛑 Выключить BIC", callback_data="bic_off")],
        [InlineKeyboardButton(text="🔄 Выбрать уровень защиты", callback_data="select_security_level")]
    ]
)

analytics_kb = InlineKeyboardMarkup(
    inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Обновить аналитику", callback_data="refresh_analytics")]
    ]
)

# ===== Cloudflare API Functions =====
async def get_security_level():
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/settings/security_level"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    logging.error(f"Security level API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Security level API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                level = data.get("result", {}).get("value", "unknown")
                return f"👁️ Текущий уровень защиты: <b>{level}</b>"
        except aiohttp.ClientError as e:
            logging.error(f"Security level connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}"

async def set_security_level(level):
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/settings/security_level"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"value": level}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.patch(url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    logging.error(f"Set security level API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}", f"Ошибка API: {resp.status}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Set security level API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}", f"Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                return f"✅ Уровень защиты установлен: <b>{level}</b>", f"Уровень защиты установлен: {level}"
        except aiohttp.ClientError as e:
            logging.error(f"Set security level connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}", f"Ошибка соединения с Cloudflare: {str(e)}"

async def get_security_analytics():
    url = "https://api.cloudflare.com/client/v4/graphql"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    past_24h = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).replace(microsecond=0).isoformat() + "Z"
    
    query = """
    query {
        viewer {
            zones(filter: {zoneTag: "%s"}) {
                httpRequests1hGroups(
                    limit: 24
                    filter: { datetime_geq: "%s", datetime_leq: "%s" }
                    orderBy: [datetime_DESC]
                ) {
                    sum {
                        requests
                        threats
                        cachedRequests
                    }
                    dimensions {
                        datetime
                    }
                }
            }
        }
    }
    """ % (CLOUDFLARE_ZONE_ID, past_24h, now)
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, headers=headers, json={"query": query}) as resp:
                if resp.status != 200:
                    logging.error(f"Analytics API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}", f"Ошибка API: {resp.status}"
                data = await resp.json()
                logging.info(f"Analytics API response: {data}")
                errors = data.get("errors")
                if errors:
                    logging.error(f"GraphQL error: {errors}")
                    return f"❌ Ошибка GraphQL: {errors[0].get('message', 'Неизвестная ошибка')}", f"Ошибка GraphQL: {errors[0].get('message', 'Неизвестная ошибка')}"
                zones = data.get("data", {}).get("viewer", {}).get("zones", [])
                if not zones:
                    logging.warning("No zones found in analytics response")
                    return "📊 Аналитика недоступна: зона не найдена.", "Аналитика недоступна: зона не найдена."
                http_requests = zones[0].get("httpRequests1hGroups", [])
                if not http_requests:
                    logging.warning("No analytics data for the last 24 hours")
                    return "📊 Аналитика недоступна: данные за последние 24 часа отсутствуют.", "Аналитика недоступна: данные за последние 24 часа отсутствуют."
                total_requests = sum(group["sum"]["requests"] for group in http_requests)
                total_threats = sum(group["sum"]["threats"] for group in http_requests)
                cached_requests = sum(group["sum"]["cachedRequests"] for group in http_requests)
                served_by_origin = total_requests - cached_requests
                message = (
                    f"📊 Аналитика запросов (последние 24 часа):\n"
                    f"Всего запросов: <b>{total_requests}</b>\n"
                    f"Обслужено Cloudflare: <b>{cached_requests}</b>\n"
                    f"Обслужено сервером: <b>{served_by_origin}</b>"
                )
                alert = f"Аналитика запросов: {total_requests} запросов, {cached_requests} обслужено Cloudflare, {served_by_origin} обслужено сервером"
                return message, alert
        except aiohttp.ClientError as e:
            logging.error(f"Analytics connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}", f"Ошибка соединения с Cloudflare: {str(e)}"

async def get_bot_fight_mode_status():
    """
    Get Bot Fight Mode status for Free plan.
    WARNING: BFM may block legitimate API or mobile app traffic. Disable if issues occur.
    See: https://developers.cloudflare.com/bots/get-started/free/
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/bot_management"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    logging.error(f"Bot Fight Mode status API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Bot Fight Mode status API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                state = data.get("result", {}).get("fight_mode", False)
                return "on" if state is True else "off"
        except aiohttp.ClientError as e:
            logging.error(f"Bot Fight Mode status connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}"

async def set_bot_fight_mode(state):
    """
    Set Bot Fight Mode on or off for Free plan.
    WARNING: BFM may block legitimate API or mobile app traffic. Disable if issues occur.
    See: https://developers.cloudflare.com/bots/get-started/free/
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/bot_management"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"super_fight_mode": state == "on"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.put(url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    logging.error(f"Bot Fight Mode API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}", f"Ошибка API: {resp.status}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Set Bot Fight Mode API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}", f"Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                state_str = "включен" if state == "on" else "выключен"
                return f"✅ Bot Fight Mode {state_str}: <b>{state}</b>", f"Bot Fight Mode {state_str}: {state}"
        except aiohttp.ClientError as e:
            logging.error(f"Bot Fight Mode connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}", f"Ошибка соединения с Cloudflare: {str(e)}"

async def get_browser_integrity_check_status():
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/settings/browser_check"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    logging.error(f"Browser Integrity Check status API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Browser Integrity Check status API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                state = data.get("result", {}).get("value", "unknown")
                return state
        except aiohttp.ClientError as e:
            logging.error(f"Browser Integrity Check status connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}"

async def set_browser_integrity_check(state):
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/settings/browser_check"
    headers = {
        "X-Auth-Email": CLOUDFLARE_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"value": state}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.patch(url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    logging.error(f"Browser Integrity Check API error: {resp.status} - {await resp.text()}")
                    return f"❌ Ошибка API: {resp.status} - {await resp.text()}", f"Ошибка API: {resp.status}"
                data = await resp.json()
                if not data.get("success"):
                    logging.error(f"Set Browser Integrity Check API failed: {data.get('errors')}")
                    return f"❌ Ошибка API: {data.get('errors', 'Неизвестная ошибка')}", f"Ошибка API: {data.get('errors', 'Неизвестная ошибка')}"
                state_str = "включена" if state == "on" else "выключена"
                return f"✅ Browser Integrity Check {state_str}: <b>{state}</b>", f"Browser Integrity Check {state_str}: {state}"
        except aiohttp.ClientError as e:
            logging.error(f"Browser Integrity Check connection error: {str(e)}")
            return f"❌ Ошибка соединения с Cloudflare: {str(e)}", f"Ошибка соединения с Cloudflare: {str(e)}"

# ===== Handlers =====
@dp.message(Command("start"))
async def start(message: types.Message):
    if message.from_user.id not in ALLOWED_USERS:
        await message.answer("🚫 У вас нет доступа к этому боту.")
        return
    try:
        await message.answer("Васап ма бой выбери кнопку:", parse_mode="HTML", reply_markup=main_kb)
    except TelegramNetworkError as e:
        logging.error(f"Telegram start timeout: {str(e)}")

@dp.message()
async def handle_buttons(message: types.Message):
    if message.from_user.id not in ALLOWED_USERS:
        await message.answer("🚫 У вас нет доступа к этому боту.")
        return
    try:
        if message.text == "🛡️ Включить защиту":
            result, _ = await set_security_level("under_attack")
            await message.answer(result, parse_mode="HTML")
        elif message.text == "⚪ Выключить защиту":
            result, _ = await set_security_level("essentially_off")
            await message.answer(result, parse_mode="HTML")
        elif message.text == "👁️ Показать текущий уровень":
            level = await get_security_level()
            await message.answer(level, parse_mode="HTML")
        elif message.text == "📊 Показать аналитику":
            analytics, _ = await get_security_analytics()
            await message.answer(analytics, parse_mode="HTML", reply_markup=analytics_kb)
        elif message.text == "🔒 Anti-DDoS":
            bfm_status = await get_bot_fight_mode_status()
            bic_status = await get_browser_integrity_check_status()
            status_message = (
                f"🔒 Статус Anti-DDoS:\n"
                f"Bot Fight Mode: <b>{bfm_status}</b>\n"
                f"Browser Integrity Check: <b>{bic_status}</b>"
            )
            await message.answer(status_message, reply_markup=anti_ddos_kb, parse_mode="HTML")
    except TelegramNetworkError as e:
        logging.error(f"Telegram button timeout: {str(e)}")
        await message.answer(f"⚠️ Ошибка Telegram: {str(e)}", parse_mode="HTML")

@dp.callback_query()
async def callbacks(query: CallbackQuery):
    if query.from_user.id not in ALLOWED_USERS:
        await query.answer("🚫 Нет доступа.", show_alert=True)
        return
    try:
        if query.data in ["essentially_off", "low", "medium", "high", "under_attack"]:
            result, alert = await set_security_level(query.data)
            await query.answer(alert, show_alert=True)
            await query.message.edit_text(result, reply_markup=level_kb, parse_mode="HTML")
        elif query.data == "select_security_level":
            await query.message.edit_text("Выберите уровень защиты:", reply_markup=level_kb, parse_mode="HTML")
        elif query.data == "refresh_analytics":
            analytics, _ = await get_security_analytics()
            await query.message.edit_text(analytics, reply_markup=analytics_kb, parse_mode="HTML")
        elif query.data in ["bfm_on", "bfm_off"]:
            state = "on" if query.data == "bfm_on" else "off"
            result, alert = await set_bot_fight_mode(state)
            await query.answer(alert, show_alert=True)
            bfm_status = await get_bot_fight_mode_status()
            bic_status = await get_browser_integrity_check_status()
            status_message = (
                f"🔒 Статус Anti-DDoS:\n"
                f"Bot Fight Mode: <b>{bfm_status}</b>\n"
                f"Browser Integrity Check: <b>{bic_status}</b>"
            )
            await query.message.edit_text(status_message, reply_markup=anti_ddos_kb, parse_mode="HTML")
        elif query.data in ["bic_on", "bic_off"]:
            state = "on" if query.data == "bic_on" else "off"
            result, alert = await set_browser_integrity_check(state)
            await query.answer(alert, show_alert=True)
            bfm_status = await get_bot_fight_mode_status()
            bic_status = await get_browser_integrity_check_status()
            status_message = (
                f"🔒 Статус Anti-DDoS:\n"
                f"Bot Fight Mode: <b>{bfm_status}</b>\n"
                f"Browser Integrity Check: <b>{bic_status}</b>"
            )
            await query.message.edit_text(status_message, reply_markup=anti_ddos_kb, parse_mode="HTML")
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            if query.data == "refresh_analytics":
                await query.message.edit_text("📊 Данные аналитики не изменились.", reply_markup=analytics_kb, parse_mode="HTML")
            elif query.data in ["bfm_on", "bfm_off", "bic_on", "bic_off"]:
                bfm_status = await get_bot_fight_mode_status()
                bic_status = await get_browser_integrity_check_status()
                status_message = (
                    f"🔒 Статус Anti-DDoS не изменился:\n"
                    f"Bot Fight Mode: <b>{bfm_status}</b>\n"
                    f"Browser Integrity Check: <b>{bic_status}</b>"
                )
                await query.message.edit_text(status_message, reply_markup=anti_ddos_kb, parse_mode="HTML")
            else:
                await query.message.edit_text("⚠️ Данные не изменились.", reply_markup=query.message.reply_markup, parse_mode="HTML")
        else:
            logging.error(f"Telegram bad request: {str(e)}")
            await query.answer(f"⚠️ Ошибка Telegram: {str(e)}", show_alert=True)
    except TelegramNetworkError as e:
        logging.error(f"Telegram callback timeout: {str(e)}")
        await query.answer("⚠️ Не удалось обновить данные из-за ошибки Telegram.", show_alert=True)
    except Exception as e:
        logging.error(f"Callback error: {str(e)}")
        await query.answer(f"⚠️ Ошибка: {str(e)}", show_alert=True)

# ===== Run Bot =====
if __name__ == "__main__":
    asyncio.run(dp.start_polling(bot))