#!/bin/sh
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CONFIG_FILE="${PTT_CHECK_CONFIG:-$SCRIPT_DIR/.ptt-check.env}"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "錯誤：找不到設定檔：$CONFIG_FILE" >&2
  exit 64
fi

set -a
# shellcheck disable=SC1090
. "$CONFIG_FILE"
set +a

command -v python3 >/dev/null 2>&1 || {
  echo "錯誤：找不到 python3。" >&2
  exit 127
}

command -v ssh >/dev/null 2>&1 || {
  echo "錯誤：找不到 ssh。" >&2
  exit 127
}

LOCK_DIR="${TMPDIR:-/tmp}/ptt-check-${USER:-$(id -u)}.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "錯誤：已有另一個 PTT 檢查程序正在執行。" >&2
  exit 75
fi

trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT HUP INT TERM

python3 - <<'PY'
import base64
import codecs
import datetime as dt
import errno
import fcntl
import hashlib
import hmac
import html
import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ============================================================
# Helpers
# ============================================================

def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"缺少必要設定：{name}")
    return value


def env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} 必須是整數") from exc
    return max(minimum, min(maximum, value))


def env_float(name, default, minimum, maximum):
    try:
        value = float(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} 必須是數字") from exc
    return max(minimum, min(maximum, value))


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def log(message):
    print(f"[{now()}] {message}", flush=True)


def has(text, *phrases):
    lowered = text.lower()
    return any(phrase.lower() in lowered for phrase in phrases)


def parse_retry_delays():
    """
    Preferred setting:
      PTT_MONEY_RETRY_DELAYS='1,2'

    Backward compatible settings:
      PTT_MONEY_RETRY_COUNT='1'
      PTT_MONEY_RETRY_DELAY='2'
    """
    raw = os.environ.get("PTT_MONEY_RETRY_DELAYS", "").strip()

    if raw:
        delays = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                delay = float(part)
            except ValueError as exc:
                raise ValueError(
                    "PTT_MONEY_RETRY_DELAYS 必須是逗號分隔的秒數，例如 1,2"
                ) from exc
            delays.append(max(0.5, min(15.0, delay)))
        return delays[:3]

    legacy_count_raw = os.environ.get("PTT_MONEY_RETRY_COUNT")
    legacy_delay_raw = os.environ.get("PTT_MONEY_RETRY_DELAY")

    if legacy_count_raw is not None or legacy_delay_raw is not None:
        count = env_int("PTT_MONEY_RETRY_COUNT", 1, 0, 3)
        delay = env_float("PTT_MONEY_RETRY_DELAY", 2.0, 0.5, 15.0)
        return [delay] * count

    return [1.0, 2.0]


# ============================================================
# Configuration
# ============================================================

def load_account_configs():
    """
    Multi-account format (recommended):

      PTT_ACCOUNT_COUNT='2'
      PTT_ACCOUNT_1='account1'
      PTT_PASSWORD_1='password1'
      PTT_ACCOUNT_LABEL_1='Main'
      PTT_TOTP_SECRET_1='...'
      PTT_2FA_RECOVERY_CODE_1='...'

      PTT_ACCOUNT_2='account2'
      ...

    If PTT_ACCOUNT_COUNT is omitted but PTT_ACCOUNT_1 exists, consecutive
    indexed accounts are auto-detected up to 10 accounts.

    Legacy single-account format remains supported:

      PTT_ACCOUNT='account'
      PTT_PASSWORD='password'
      PTT_TOTP_SECRET='...'
      PTT_2FA_RECOVERY_CODE='...'
    """
    count_raw = os.environ.get("PTT_ACCOUNT_COUNT", "").strip()
    indexed_mode = bool(
        count_raw
        or os.environ.get("PTT_ACCOUNT_1", "").strip()
        or os.environ.get("PTT_PASSWORD_1", "").strip()
    )

    configs = []

    if indexed_mode:
        if count_raw:
            try:
                count = int(count_raw)
            except ValueError as exc:
                raise ValueError("PTT_ACCOUNT_COUNT 必須是整數") from exc
            if not 1 <= count <= 10:
                raise ValueError("PTT_ACCOUNT_COUNT 必須介於 1 到 10")
        else:
            count = 0
            for index in range(1, 11):
                account = os.environ.get(f"PTT_ACCOUNT_{index}", "").strip()
                password = os.environ.get(f"PTT_PASSWORD_{index}", "")
                if not account and not password:
                    break
                if not account or not password:
                    raise ValueError(
                        f"PTT_ACCOUNT_{index} 與 PTT_PASSWORD_{index} 必須同時設定"
                    )
                count = index

            if count == 0:
                raise ValueError("找不到任何 PTT_ACCOUNT_n / PTT_PASSWORD_n 設定")

        for index in range(1, count + 1):
            account = os.environ.get(f"PTT_ACCOUNT_{index}", "").strip()
            password = os.environ.get(f"PTT_PASSWORD_{index}", "")

            if not account:
                raise ValueError(f"缺少必要設定：PTT_ACCOUNT_{index}")
            if not password:
                raise ValueError(f"缺少必要設定：PTT_PASSWORD_{index}")

            label = (
                os.environ.get(f"PTT_ACCOUNT_LABEL_{index}", "").strip()
                or account
            )[:64]
            totp_secret = re.sub(
                r"[\s-]+",
                "",
                os.environ.get(f"PTT_TOTP_SECRET_{index}", ""),
            ).upper()
            recovery_code = re.sub(
                r"\s+",
                "",
                os.environ.get(f"PTT_2FA_RECOVERY_CODE_{index}", ""),
            )

            configs.append(
                {
                    "index": index,
                    "account": account,
                    "password": password,
                    "label": label,
                    "totp_secret": totp_secret,
                    "recovery_code": recovery_code,
                }
            )

        return configs

    # Legacy single-account mode.
    account = required("PTT_ACCOUNT")
    password = required("PTT_PASSWORD")
    label = (os.environ.get("PTT_ACCOUNT_LABEL", "").strip() or account)[:64]
    totp_secret = re.sub(
        r"[\s-]+",
        "",
        os.environ.get("PTT_TOTP_SECRET", ""),
    ).upper()
    recovery_code = re.sub(
        r"\s+",
        "",
        os.environ.get("PTT_2FA_RECOVERY_CODE", ""),
    )

    return [
        {
            "index": 1,
            "account": account,
            "password": password,
            "label": label,
            "totp_secret": totp_secret,
            "recovery_code": recovery_code,
        }
    ]


try:
    ACCOUNT_CONFIGS = load_account_configs()
    BOT_TOKEN = required("TELEGRAM_BOT_TOKEN")
    CHAT_ID = required("TELEGRAM_CHAT_ID")
except ValueError as exc:
    print(f"設定錯誤：{exc}", file=sys.stderr)
    sys.exit(64)

HOST = os.environ.get("PTT_HOST", "ptt.cc").strip() or "ptt.cc"
PORT = env_int("PTT_PORT", 22, 1, 65535)
CONNECT_TIMEOUT = env_int("PTT_CONNECT_TIMEOUT", 15, 5, 120)
SESSION_TIMEOUT = env_int("PTT_SESSION_TIMEOUT", 75, 30, 240)
KICK_DUPLICATE = env_bool("PTT_KICK_DUPLICATE", False)
ACCOUNT_DELAY = env_float("PTT_ACCOUNT_DELAY", 1.0, 0.0, 30.0)

TELEGRAM_SILENT = env_bool("TELEGRAM_SILENT", False)
TELEGRAM_DRY_RUN = env_bool("TELEGRAM_DRY_RUN", False)
THREAD_ID = os.environ.get("TELEGRAM_MESSAGE_THREAD_ID", "").strip()

SYSTEM_HOSTNAME = socket.gethostname()
SERVER_NAME = os.environ.get("SERVER_NAME", "").strip() or SYSTEM_HOSTNAME

MONEY_RETRY_DELAYS = parse_retry_delays()
TFA_MAX_ATTEMPTS = env_int("PTT_2FA_MAX_ATTEMPTS", 2, 1, 4)

LOG_DIR = Path(
    os.environ.get(
        "PTT_LOG_DIR",
        str(Path.home() / ".local" / "state" / "ptt-check"),
    )
).expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)
try:
    LOG_DIR.chmod(0o700)
except OSError:
    pass

HISTORY_MAX_MB = env_int("PTT_HISTORY_MAX_MB", 10, 1, 1024)
HISTORY_KEEP_MB = env_int("PTT_HISTORY_KEEP_MB", 5, 1, 1024)
DEBUG_MAX_MB = env_int("PTT_DEBUG_MAX_MB", 2, 1, 100)

HISTORY_MAX_BYTES = HISTORY_MAX_MB * 1024 * 1024
HISTORY_KEEP_BYTES = HISTORY_KEEP_MB * 1024 * 1024
DEBUG_MAX_BYTES = DEBUG_MAX_MB * 1024 * 1024

if HISTORY_KEEP_BYTES >= HISTORY_MAX_BYTES:
    HISTORY_KEEP_BYTES = max(1024 * 1024, HISTORY_MAX_BYTES // 2)

STARTED_AT = now()


# ============================================================
# ANSI / ECMA-48 / DEC 2026
# ============================================================

# Matches the ECMA-48 CSI grammar recommended by PTT.
ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.S)
ANSI_ESC = re.compile(r"\x1b[@-_]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SYNC_BEGIN = b"\x1b[?2026h"
SYNC_END = b"\x1b[?2026l"
SYNC_TAIL_LEN = max(len(SYNC_BEGIN), len(SYNC_END)) - 1


def clean(text):
    output = []
    for char in text:
        if char == "\b":
            if output:
                output.pop()
        else:
            output.append(char)

    text = "".join(output)
    text = ANSI_OSC.sub("", text)
    text = ANSI_CSI.sub("", text)
    text = ANSI_ESC.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = CONTROL.sub("", text).replace("�", "")
    return re.sub(r"[ \t]+", " ", text)


# ============================================================
# TOTP
# ============================================================

def validate_totp_secret(secret):
    if not secret:
        return None

    if not re.fullmatch(r"[A-Z2-7]+", secret):
        raise ValueError("PTT_TOTP_SECRET 不是有效的 Base32 secret")

    try:
        padding = "=" * ((8 - len(secret) % 8) % 8)
        return base64.b32decode(secret + padding, casefold=True)
    except Exception as exc:
        raise ValueError("PTT_TOTP_SECRET 無法解碼") from exc


def prepare_account_configs(configs):
    """Validate all 2FA settings before opening any SSH session."""
    prepared = []

    for config in configs:
        item = dict(config)
        try:
            item["totp_key"] = validate_totp_secret(item["totp_secret"])
        except ValueError as exc:
            raise ValueError(
                f"帳號 {item['account']} 的 PTT_TOTP_SECRET 設定錯誤：{exc}"
            ) from exc

        recovery_code = item["recovery_code"]
        if recovery_code and not re.fullmatch(r"\d{8}", recovery_code):
            raise ValueError(
                f"帳號 {item['account']} 的 PTT_2FA_RECOVERY_CODE 必須是 8 位數字"
            )

        prepared.append(item)

    return prepared


try:
    ACCOUNT_CONFIGS = prepare_account_configs(ACCOUNT_CONFIGS)
except ValueError as exc:
    print(f"設定錯誤：{exc}", file=sys.stderr)
    sys.exit(64)


def generate_totp(totp_key, previous=None):
    if totp_key is None:
        raise RuntimeError("未設定 PTT_TOTP_SECRET")

    while True:
        timestamp = int(time.time())
        remaining = 30 - (timestamp % 30)
        counter = timestamp // 30

        digest = hmac.new(
            totp_key,
            struct.pack(">Q", counter),
            hashlib.sha1,
        ).digest()

        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        code = f"{binary % 1_000_000:06d}"

        # Avoid submitting a code that is about to expire.
        if remaining >= 5 and code != previous:
            return code

        time.sleep(min(max(remaining + 0.2, 0.5), 5.5))


# ============================================================
# PTT session
# ============================================================

class PttSession:
    ANY_KEY = (
        "按任意鍵繼續",
        "請按任意鍵",
        "press any key",
    )

    MAIN_MENU = (
        "【主功能表】",
        "主功能表",
        "(G)oodbye",
        "Goodbye離開",
        "Goodbye 離開",
    )

    TALK_MENU = (
        "Query 查詢網友",
        "Query查詢網友",
        "(Q)uery",
        "聊天說話",
    )

    QUERY_PROMPT = (
        "請輸入使用者代號",
        "請輸入網友代號",
        "請輸入查詢代號",
        "使用者代號:",
        "使用者代號：",
        "網友代號:",
        "網友代號：",
    )

    PROFILE_ERROR = (
        "沒有這個代號",
        "查無此人",
        "無此代號",
    )

    TFA_SUCCESS = (
        "2FA 兩階段驗證成功",
        "兩階段驗證成功",
        "密碼正確！ 開始登入系統",
        "密碼正確！開始登入系統",
    )

    TFA_WRONG = (
        "驗證碼錯誤",
        "請確定在時限前輸入完畢",
    )

    TFA_TOO_MANY = (
        "兩階段驗證失敗次數過多",
    )

    def __init__(self, account_config):
        self.account_config = account_config
        self.account = account_config["account"]
        self.password = account_config["password"]
        self.account_label = account_config["label"]
        self.totp_secret = account_config["totp_secret"]
        self.recovery_code = account_config["recovery_code"]
        self.totp_key = account_config["totp_key"]
        self.log_name = (
            self.account
            if self.account_label == self.account
            else f"{self.account_label}/{self.account}"
        )

        self.master = None
        self.proc = None
        self.decoder = codecs.getincrementaldecoder("cp950")(errors="replace")
        self.transcript = ""
        self.events = []
        self.debug_sections = []
        self.started = time.monotonic()
        self.started_at = now()
        self.query_method = None

        self.two_factor_required = False
        self.two_factor_verified = False
        self.two_factor_method = None
        self.sensitive_codes = set()

        self.sync_output = False
        self.sync_scan_tail = b""
        self.dec2026_seen = False
        self.dec2026_batches = 0

    def event(self, message):
        event_text = f"[{self.log_name}] {message}"
        self.events.append(f"[{now()}] {event_text}")
        log(event_text)

    def _track_sync_output(self, data):
        scan = self.sync_scan_tail + data
        cursor = 0

        while True:
            begin_at = scan.find(SYNC_BEGIN, cursor)
            end_at = scan.find(SYNC_END, cursor)

            if begin_at == -1 and end_at == -1:
                break

            if begin_at != -1 and (end_at == -1 or begin_at < end_at):
                self.sync_output = True
                self.dec2026_seen = True
                self.dec2026_batches += 1
                cursor = begin_at + len(SYNC_BEGIN)
            else:
                self.sync_output = False
                self.dec2026_seen = True
                cursor = end_at + len(SYNC_END)

        if SYNC_TAIL_LEN > 0:
            self.sync_scan_tail = scan[-SYNC_TAIL_LEN:]

    def analysis_ready(self):
        return not self.sync_output

    def start(self):
        self.master, slave = pty.openpty()

        try:
            fcntl.ioctl(
                self.master,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 24, 80, 0, 0),
            )
        except OSError:
            pass

        command = [
            "ssh",
            "-tt",
            "-p",
            str(PORT),
            "-o",
            f"ConnectTimeout={CONNECT_TIMEOUT}",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "BatchMode=yes",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            f"bbs@{HOST}",
        ]

        child_env = os.environ.copy()
        child_env["TERM"] = "xterm"

        self.proc = subprocess.Popen(
            command,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            env=child_env,
        )

        os.close(slave)
        os.set_blocking(self.master, False)
        self.event(f"已啟動 SSH：bbs@{HOST}:{PORT}")

    def send(self, data, message=None):
        view = memoryview(data)

        while view:
            try:
                count = os.write(self.master, view)
                view = view[count:]
            except BlockingIOError:
                select.select([], [self.master], [], 0.2)
            except OSError as exc:
                if exc.errno in {errno.EIO, errno.EBADF}:
                    return
                raise

        if message:
            self.event(message)

    def read_once(self, timeout=0.2):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return

        try:
            data = os.read(self.master, 65536)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno in {errno.EIO, errno.EBADF}:
                return
            raise

        if not data:
            return

        self._track_sync_output(data)
        self.transcript += self.decoder.decode(data)

        if len(self.transcript) > 600000:
            self.transcript = self.transcript[-500000:]

    def read_for(self, seconds):
        deadline = time.monotonic() + seconds

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            self.read_once(min(0.2, remaining))
            if self.proc.poll() is not None:
                break

    def since(self, position):
        return clean(self.transcript[position:])

    def wait_for(self, phrases, timeout, position):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            self.read_once(0.20)
            text = self.since(position)

            # PTT DEC 2026 synchronized output: do not analyze a partial batch.
            if self.analysis_ready() and has(text, *phrases):
                return True, text

            if self.proc.poll() is not None:
                return False, text

        return False, self.since(position)

    def wait_for_predicate(self, predicate, timeout, position):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            self.read_once(0.20)
            text = self.since(position)

            if self.analysis_ready() and predicate(text):
                return True, text

            if self.proc.poll() is not None:
                return False, text

        return False, self.since(position)

    def capture(self, label, position):
        text = self.since(position)[-10000:]
        self.debug_sections.append(f"===== {label} =====\n{text}")
        self.debug_sections = self.debug_sections[-30:]

    def dismiss_prompt(self, label, known_text=""):
        if known_text and not has(known_text, *self.ANY_KEY):
            return None

        marker = len(self.transcript)
        self.send(
            b"\r",
            f"{label}：已清除『按任意鍵繼續』提示",
        )
        return marker

    @staticmethod
    def is_2fa_prompt(text):
        normalized = re.sub(r"\s+", "", text).lower()
        factor_marker = ("2fa" in normalized) or ("兩階段" in normalized)
        input_marker = any(
            token in normalized
            for token in (
                "驗證碼",
                "totp",
                "救援碼",
                "限時數字",
            )
        )
        success_marker = "驗證成功" in normalized
        return factor_marker and input_marker and not success_marker

    @staticmethod
    def is_profile_ready(text):
        normalized = re.sub(r"\s+", "", text)
        primary = (
            "登入次數" in normalized
            and "經濟狀況" in normalized
            and "私人信箱" in normalized
        )
        fallback = (
            "登入次數" in normalized
            and "上次故鄉" in normalized
            and "經濟狀況" in normalized
        )
        return primary or fallback

    # --------------------------------------------------------
    # 2FA
    # --------------------------------------------------------

    def handle_2fa(self):
        self.two_factor_required = True
        self.event("已偵測到 PTT 兩階段驗證")

        if self.totp_key is None and not self.recovery_code:
            return (
                False,
                "PTT 要求兩階段驗證，但未設定 PTT_TOTP_SECRET",
            )

        previous_totp = None
        recovery_used = False

        for attempt in range(1, TFA_MAX_ATTEMPTS + 1):
            if self.totp_key is not None:
                code = generate_totp(self.totp_key, previous_totp)
                previous_totp = code
                method = "totp"
                label = "6 位 TOTP"
            elif self.recovery_code and not recovery_used:
                code = self.recovery_code
                recovery_used = True
                method = "recovery_code"
                label = "8 位救援碼"
            else:
                break

            self.sensitive_codes.add(code)
            marker = len(self.transcript)

            self.send(
                code.encode("ascii") + b"\r",
                f"已送出 {label}（第 {attempt} 次）",
            )

            ok, text = self.wait_for(
                self.TFA_SUCCESS + self.TFA_WRONG + self.TFA_TOO_MANY,
                8.0,
                marker,
            )

            self.capture(f"2FA 驗證第 {attempt} 次結果", marker)

            if has(text, *self.TFA_SUCCESS):
                self.two_factor_verified = True
                self.two_factor_method = method
                self.event("PTT 兩階段驗證成功")
                return True, ""

            if has(text, *self.TFA_TOO_MANY):
                return False, "PTT 兩階段驗證失敗次數過多"

            if has(text, *self.TFA_WRONG):
                self.event(f"PTT 兩階段驗證碼錯誤（第 {attempt} 次）")
                if method == "recovery_code":
                    return False, "PTT 兩階段救援碼驗證失敗"
                continue

            if not ok:
                return False, "送出 PTT 兩階段驗證碼後等待結果逾時"

        return False, "PTT 兩階段驗證失敗"

    # --------------------------------------------------------
    # Login
    # --------------------------------------------------------

    def login(self):
        start = len(self.transcript)

        ok, text = self.wait_for(
            (
                "請輸入代號",
                "請輸入帳號",
                "您的代號",
                "以 guest 參觀",
                "user bbs is not recognized",
                "permission denied",
                "connection refused",
                "could not resolve",
            ),
            CONNECT_TIMEOUT + 10,
            start,
        )

        self.capture("SSH 與 PTT 登入畫面", start)

        if not ok:
            return False, "SSH 已連線，但未偵測到 PTT 帳號輸入畫面"

        if has(
            text,
            "user bbs is not recognized",
            "permission denied",
            "connection refused",
            "could not resolve",
        ):
            return False, "無法以 SSH 使用者 bbs 連入 PTT"

        self.send(
            self.account.encode("ascii", errors="ignore") + b"\r",
            "已送出 PTT 帳號",
        )

        start = len(self.transcript)
        ok, text = self.wait_for(
            (
                "請輸入您的密碼",
                "請輸入密碼",
                "密碼:",
                "密碼：",
                "沒有這個代號",
                "無此代號",
                "查無此人",
            ),
            12,
            start,
        )

        self.capture("PTT 密碼提示", start)

        if not ok:
            return False, "已送出 PTT 帳號，但未偵測到 PTT 密碼輸入畫面"

        if has(text, "沒有這個代號", "無此代號", "查無此人"):
            return False, "PTT 帳號不存在或未被辨識"

        self.send(self.password.encode("utf-8") + b"\r", "已送出 PTT 密碼")

        position = len(self.transcript)
        deadline = time.monotonic() + min(50, SESSION_TIMEOUT)
        duplicate_done = False

        while time.monotonic() < deadline:
            self.read_once(0.20)
            text = self.since(position)

            if not self.analysis_ready():
                continue

            if has(
                text,
                "密碼不對",
                "密碼錯誤",
                "登入失敗",
                "wrong password",
                "authentication failed",
            ):
                return False, "PTT 帳號或密碼驗證失敗"

            if (
                not duplicate_done
                and has(
                    text,
                    "重複登入",
                    "重覆登入",
                    "刪除其他連線",
                    "刪除以上連線",
                )
            ):
                self.send(b"y\r" if KICK_DUPLICATE else b"n\r")
                duplicate_done = True
                self.event("已處理重複登入詢問")
                position = len(self.transcript)
                continue

            if self.is_2fa_prompt(text):
                self.capture("PTT 兩階段驗證提示", position)
                tfa_ok, tfa_error = self.handle_2fa()
                if not tfa_ok:
                    return False, tfa_error
                position = len(self.transcript)
                continue

            if has(text, *self.MAIN_MENU):
                self.read_for(0.3)
                self.event("已登入並進入 PTT 主功能表")
                return True, ""

            if has(text, *self.ANY_KEY):
                marker = self.dismiss_prompt("登入後", text)
                ok, next_text = self.wait_for(self.MAIN_MENU, 10.0, marker)
                self.capture("清除登入提示後的畫面", marker)

                if ok:
                    self.event("已登入並進入 PTT 主功能表")
                    return True, ""

                if has(next_text, *self.ANY_KEY):
                    position = marker
                    continue

                return False, "已清除登入提示，但無法偵測 PTT 主功能表"

            if has(text, "系統過載", "系統忙碌", "人數太多"):
                return False, "PTT 系統目前過載或忙碌"

            if self.proc.poll() is not None:
                return False, "SSH 工作階段在登入完成前結束"

        return False, "已送出 PTT 密碼，但無法偵測主功能表"

    # --------------------------------------------------------
    # Navigation
    # --------------------------------------------------------

    def ensure_main_menu(self):
        for attempt in range(1, 7):
            marker = len(self.transcript)

            self.send(b"\x03")       # Ctrl+C
            self.read_for(0.20)
            self.send(b"\x1b[D")    # Left
            self.read_for(0.30)
            self.send(b"\x0c")      # Ctrl+L

            ok, text = self.wait_for(
                self.MAIN_MENU + self.ANY_KEY,
                3.0,
                marker,
            )

            if has(text, *self.ANY_KEY):
                prompt_marker = self.dismiss_prompt(
                    f"返回主功能表第 {attempt} 次",
                    text,
                )

                if has(text, *self.MAIN_MENU):
                    return True

                ok, text = self.wait_for(
                    self.MAIN_MENU,
                    3.0,
                    prompt_marker,
                )

            if ok and has(text, *self.MAIN_MENU):
                return True

        return False

    def enter_talk(self):
        if not self.ensure_main_menu():
            return False

        for attempt in range(1, 4):
            marker = len(self.transcript)

            self.send(
                b"T\r",
                f"已送出 T + Enter 執行 Talk（第 {attempt} 次）",
            )

            ok, text = self.wait_for(
                self.TALK_MENU + self.ANY_KEY,
                5.0,
                marker,
            )

            self.capture(f"進入 Talk 第 {attempt} 次", marker)
            talk_seen = has(text, *self.TALK_MENU)

            if has(text, *self.ANY_KEY):
                prompt_marker = self.dismiss_prompt("Talk 選單", text)

                if talk_seen:
                    self.read_for(0.3)
                    self.event("已進入休閒聊天區並完成提示清除")
                    return True

                ok, text = self.wait_for(
                    self.TALK_MENU,
                    3.0,
                    prompt_marker,
                )

                if ok:
                    self.event("已進入休閒聊天區並完成提示清除")
                    return True

            elif ok and talk_seen:
                self.event("已進入休閒聊天區")
                return True

            self.ensure_main_menu()

        return False

    def open_query_prompt(self):
        if not self.enter_talk():
            return False

        for attempt in range(1, 4):
            marker = len(self.transcript)

            self.send(
                b"Q\r",
                f"已送出 Q + Enter 執行 Query（第 {attempt} 次）",
            )

            ok, text = self.wait_for(
                self.QUERY_PROMPT + self.ANY_KEY,
                4.0,
                marker,
            )

            self.capture(f"開啟 Query 第 {attempt} 次", marker)

            if has(text, *self.QUERY_PROMPT):
                self.event("已偵測到 Query 使用者代號提示")
                return True

            if has(text, *self.ANY_KEY):
                self.dismiss_prompt("Query 前", text)
                self.read_for(0.4)
                continue

            self.send(b"\x0c")
            self.read_for(0.4)

        return False

    def query_profile(self):
        if not self.open_query_prompt():
            return False, ""

        marker = len(self.transcript)

        self.send(
            self.account.encode("ascii", errors="ignore") + b"\r",
            "已在 Query 提示中送出 PTT 帳號",
        )

        ok, text = self.wait_for_predicate(
            lambda value: (
                self.is_profile_ready(value)
                or has(value, *self.PROFILE_ERROR)
            ),
            15.0,
            marker,
        )

        # On old/non-DEC2026 behavior, allow the remaining fields to arrive.
        self.read_for(0.6)
        text = self.since(marker)

        self.capture("PTT 使用者資料查詢結果", marker)

        if has(text, *self.PROFILE_ERROR):
            return False, text

        if not ok or not self.is_profile_ready(text):
            return False, text

        self.query_method = "Talk > Q+Enter > ID"
        self.event("已取得自己的 PTT 使用者資料頁")
        return True, text

    # --------------------------------------------------------
    # Logout
    # --------------------------------------------------------

    def logout(self):
        if not self.proc or self.proc.poll() is not None:
            return False, "already_closed"

        self.send(b"\r")
        self.read_for(0.6)

        if not self.ensure_main_menu():
            return False, "ssh_disconnect"

        marker = len(self.transcript)

        self.send(
            b"G\r",
            "已送出 G + Enter 執行 Goodbye",
        )

        deadline = time.monotonic() + 8.0
        confirmed = False

        while time.monotonic() < deadline:
            self.read_once(0.20)

            if self.proc.poll() is not None:
                self.event("已確認從 PTT 正常登出")
                return True, "normal"

            text = self.since(marker)

            if not self.analysis_ready():
                continue

            if (
                not confirmed
                and has(
                    text,
                    "確定要離開",
                    "真的要離開",
                    "您確定要離開",
                    "確定離開",
                    "要離開嗎",
                )
            ):
                self.send(b"y\r", "已確認離開 PTT")
                confirmed = True

            if has(text, *self.ANY_KEY):
                prompt_marker = self.dismiss_prompt("Goodbye", text)
                if prompt_marker is not None:
                    marker = prompt_marker

        if not confirmed:
            self.send(b"y\r")
            end = time.monotonic() + 4.0

            while time.monotonic() < end:
                self.read_once(0.20)
                if self.proc.poll() is not None:
                    self.event("已確認從 PTT 正常登出")
                    return True, "normal"

        return False, "ssh_disconnect"

    # --------------------------------------------------------
    # Debug / close
    # --------------------------------------------------------

    def debug_text(self):
        transcript = clean(self.transcript)
        sections = self.debug_sections + [
            "===== CLEAN TRANSCRIPT TAIL =====\n" + transcript[-30000:]
        ]
        sanitized = "\n\n".join(sections)

        replacements = []
        if self.password:
            replacements.append((self.password, "[PASSWORD]"))
        if self.totp_secret:
            replacements.append((self.totp_secret, "[TOTP_SECRET]"))
        if self.recovery_code:
            replacements.append((self.recovery_code, "[RECOVERY_CODE]"))
        for code in self.sensitive_codes:
            replacements.append((code, "[2FA_CODE]"))

        for secret, replacement in replacements:
            sanitized = sanitized.replace(secret, replacement)

        return sanitized

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGHUP)
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass


# ============================================================
# Query parsers
# ============================================================

def parse_login_count(text):
    patterns = [
        r"《\s*(?:登入次數|登入天數)\s*》\s*([0-9][0-9,]*)",
        r"(?:登入次數|登入天數)\s*[:：]?\s*([0-9][0-9,]*)",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.I)
        if matches:
            return int(matches[-1].replace(",", ""))

    return None


def parse_money(text):
    patterns = [
        (
            r"《\s*經濟狀況\s*》"
            r"[^\n\r]*?"
            r"\(\s*\$\s*(-?[0-9][0-9,]*)\s*\)"
        ),
        r"經濟狀況[^\n\r]*?\$\s*(-?[0-9][0-9,]*)",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.I)
        if matches:
            return int(matches[-1].replace(",", ""))

    return None


def parse_mail(text):
    normalized = re.sub(r"\s+", "", text)

    candidates = []
    for phrase, value in (
        ("有新進信件還沒看", True),
        ("最近無新信件", False),
        ("沒有新信件", False),
        ("無新信件", False),
    ):
        start = 0
        while True:
            index = normalized.find(phrase, start)
            if index == -1:
                break
            # Require the mailbox label reasonably close to the status phrase.
            mailbox_at = normalized.rfind("私人信箱", max(0, index - 80), index + 1)
            if mailbox_at != -1:
                candidates.append((index, value))
            start = index + 1

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


def parse_last_ip(text):
    patterns = [
        r"《\s*上次故鄉\s*》\s*([^\s《》]+)",
        r"上次故鄉\s*[:：]?\s*([^\s《》]+)",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.I)
        if matches:
            return matches[-1].strip(" ,;，；")[:128]

    return None


def should_retry_money(text):
    normalized = re.sub(r"\s+", "", text)
    return (
        "經濟狀況" in normalized
        and not re.search(r"\(\s*\$\s*-?[0-9]", text)
    )


def profile_says_offline(text):
    normalized = re.sub(r"\s+", "", text)
    return "目前動態》不在站上" in normalized


# ============================================================
# Log rotation
# ============================================================

def trim_jsonl_file(path, max_bytes, keep_bytes):
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return False

    if size <= max_bytes:
        return False

    temp_path = path.with_name(path.name + ".tmp")

    with path.open("rb") as source:
        start = max(0, size - keep_bytes)
        source.seek(start)
        if start > 0:
            source.readline()
        remaining = source.read()

    with temp_path.open("wb") as target:
        target.write(remaining)
        target.flush()
        try:
            os.fsync(target.fileno())
        except OSError:
            pass

    try:
        temp_path.chmod(0o600)
    except OSError:
        pass

    os.replace(temp_path, path)
    return True


def truncate_utf8_tail(text, max_bytes):
    data = text.encode("utf-8", errors="replace")

    if len(data) <= max_bytes:
        return text, False

    tail = data[-max_bytes:].decode("utf-8", errors="ignore")
    return (
        f"===== DEBUG 過大，僅保留最後約 {DEBUG_MAX_MB} MiB =====\n\n{tail}",
        True,
    )


def save_files(record, debug_text):
    last_file = LOG_DIR / "last.json"
    history_file = LOG_DIR / "history.jsonl"
    debug_file = LOG_DIR / "last-debug.txt"

    last_file.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with history_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")

    if trim_jsonl_file(
        history_file,
        HISTORY_MAX_BYTES,
        HISTORY_KEEP_BYTES,
    ):
        log(
            f"history.jsonl 超過 {HISTORY_MAX_MB} MiB，"
            f"已自動保留最新約 {HISTORY_KEEP_BYTES / 1024 / 1024:.1f} MiB 完整紀錄"
        )

    debug_text, debug_trimmed = truncate_utf8_tail(
        debug_text,
        DEBUG_MAX_BYTES,
    )

    if debug_trimmed:
        log(
            f"last-debug.txt 超過 {DEBUG_MAX_MB} MiB，"
            "已只保留最新除錯內容"
        )

    debug_file.write_text(debug_text + "\n", encoding="utf-8")

    for path in (last_file, history_file, debug_file):
        try:
            path.chmod(0o600)
        except OSError:
            pass


# ============================================================
# Telegram
# ============================================================

def status_display(status):
    return {
        "success": ("✅", "成功"),
        "partial_success": ("⚠️", "部分成功"),
        "auth_failed": ("⛔️", "驗證失敗"),
        "failed": ("❌", "失敗"),
    }.get(status, ("❔", status))


def telegram_account_name(record):
    esc = html.escape
    account = f"<code>{esc(record['account'])}</code>"
    label = record.get("account_label") or record["account"]
    if label != record["account"]:
        return f"{account}（{esc(label)}）"
    return account


def build_telegram(record):
    esc = html.escape
    accounts = record["accounts"]
    overall_icon, overall_name = status_display(record["status"])

    if len(accounts) == 1:
        item = accounts[0]
        icon, status_name = status_display(item["status"])

        if item["has_new_mail"] is True:
            mail_text = "📬 有新信"
        elif item["has_new_mail"] is False:
            mail_text = "📭 沒有新信"
        else:
            mail_text = "❔ 未取得"

        login_count = (
            "未取得"
            if item["login_count"] is None
            else f"{item['login_count']:,}"
        )
        money_text = (
            "未取得"
            if item["money"] is None
            else f"{item['money']:,}"
        )
        last_ip = item["last_login_ip"] or "未取得"

        return "\n".join(
            [
                "#PTTAutoLogin",
                "",
                f"{icon} <b>狀態：</b>{esc(status_name)}",
                f"👤 <b>帳號：</b>{telegram_account_name(item)}",
                f"📊 <b>登入次數：</b>{esc(login_count)}",
                f"💰 <b>P 幣：</b>{esc(money_text)}",
                f"✉️ <b>站內信：</b>{esc(mail_text)}",
                f"🌐 <b>上次登入位置：</b><code>{esc(last_ip)}</code>",
                f"🖥 <b>執行主機：</b><code>{esc(SERVER_NAME)}</code>",
            ]
        )

    lines = [
        "#PTTAutoLogin",
        "",
        (
            f"{overall_icon} <b>整體狀態：</b>{esc(overall_name)} "
            f"（{record['success_count']}/{record['account_count']} 成功）"
        ),
    ]

    for position, item in enumerate(accounts, start=1):
        icon, status_name = status_display(item["status"])

        if item["has_new_mail"] is True:
            mail_text = "📬 有新信"
        elif item["has_new_mail"] is False:
            mail_text = "📭 沒有新信"
        else:
            mail_text = "❔ 未取得"

        login_count = (
            "未取得"
            if item["login_count"] is None
            else f"{item['login_count']:,}"
        )
        money_text = (
            "未取得"
            if item["money"] is None
            else f"{item['money']:,}"
        )
        last_ip = item["last_login_ip"] or "未取得"

        lines.extend(
            [
                "",
                f"<b>── 帳號 {position} ──</b>",
                f"{icon} <b>狀態：</b>{esc(status_name)}",
                f"👤 <b>帳號：</b>{telegram_account_name(item)}",
                f"📊 <b>登入次數：</b>{esc(login_count)}",
                f"💰 <b>P 幣：</b>{esc(money_text)}",
                f"✉️ <b>站內信：</b>{esc(mail_text)}",
                f"🌐 <b>上次登入位置：</b><code>{esc(last_ip)}</code>",
            ]
        )

    lines.extend(
        [
            "",
            f"🖥 <b>執行主機：</b><code>{esc(SERVER_NAME)}</code>",
        ]
    )
    return "\n".join(lines)


def send_telegram(text):
    if TELEGRAM_DRY_RUN:
        print(
            "--- Telegram dry run ---\n"
            + text
            + "\n--- End Telegram dry run ---"
        )
        return True, ""

    data = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
        "disable_notification": "true" if TELEGRAM_SILENT else "false",
    }

    if THREAD_ID:
        data["message_thread_id"] = THREAD_ID

    request = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=urllib.parse.urlencode(data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(
                response.read().decode("utf-8", errors="replace")
            )

        if result.get("ok"):
            return True, ""

        return False, result.get("description", "Telegram API 未知錯誤")

    except urllib.error.HTTPError as exc:
        try:
            result = json.loads(
                exc.read().decode("utf-8", errors="replace")
            )
            return False, result.get("description", f"HTTP {exc.code}")
        except Exception:
            return False, f"HTTP {exc.code}"

    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ============================================================
# Per-account execution
# ============================================================

def run_account(account_config):
    session = PttSession(account_config)

    status = "failed"
    message = "尚未執行"
    login_count = None
    money = None
    has_new_mail = None
    last_login_ip = None
    logout_confirmed = False
    logout_method = "not_started"
    profile_text = ""
    money_retry_attempted = 0
    money_retry_succeeded = False

    try:
        session.event("開始 PTT 自動登入")
        session.start()

        login_ok, login_error = session.login()

        if not login_ok:
            status = (
                "auth_failed"
                if any(
                    token in login_error
                    for token in (
                        "密碼",
                        "兩階段",
                        "救援碼",
                        "驗證",
                    )
                )
                else "failed"
            )
            message = login_error
            session.event(login_error)

        else:
            query_ok, profile_text = session.query_profile()

            if query_ok:
                login_count = parse_login_count(profile_text)
                money = parse_money(profile_text)
                has_new_mail = parse_mail(profile_text)
                last_login_ip = parse_last_ip(profile_text)

                if (
                    money is None
                    and MONEY_RETRY_DELAYS
                    and should_retry_money(profile_text)
                ):
                    for retry_no, delay in enumerate(MONEY_RETRY_DELAYS, start=1):
                        money_retry_attempted = retry_no

                        if profile_says_offline(profile_text):
                            session.event(
                                "P 幣精確數值未顯示，且 Query 顯示『不在站上』；"
                                f"等待 {delay:g} 秒後重查（{retry_no}/{len(MONEY_RETRY_DELAYS)}）"
                            )
                        else:
                            session.event(
                                "P 幣精確數值未顯示；"
                                f"等待 {delay:g} 秒後重查（{retry_no}/{len(MONEY_RETRY_DELAYS)}）"
                            )

                        session.send(
                            b"\r",
                            "已離開目前 Query 結果頁，準備重新查詢 P 幣",
                        )
                        session.read_for(0.5)
                        time.sleep(delay)

                        retry_ok, retry_profile_text = session.query_profile()

                        if not retry_ok:
                            session.event("P 幣重查失敗：無法重新取得使用者資料頁")
                            continue

                        profile_text = retry_profile_text
                        retry_login_count = parse_login_count(profile_text)
                        retry_money = parse_money(profile_text)
                        retry_mail = parse_mail(profile_text)
                        retry_last_ip = parse_last_ip(profile_text)

                        if retry_login_count is not None:
                            login_count = retry_login_count
                        if retry_mail is not None:
                            has_new_mail = retry_mail
                        if retry_last_ip:
                            last_login_ip = retry_last_ip

                        if retry_money is not None:
                            money = retry_money
                            money_retry_succeeded = True
                            session.event(f"P 幣重查成功：{money:,}")
                            break

                        session.event(
                            f"P 幣重查後仍未顯示（{retry_no}/{len(MONEY_RETRY_DELAYS)}）"
                        )

                session.event(
                    "登入次數查詢結果："
                    + (f"{login_count:,}" if login_count is not None else "未取得")
                )
                session.event(
                    "P 幣查詢結果："
                    + (f"{money:,}" if money is not None else "未取得")
                )

                if has_new_mail is True:
                    mail_result = "有新信"
                elif has_new_mail is False:
                    mail_result = "沒有新信"
                else:
                    mail_result = "未取得"

                session.event("站內信檢查結果：" + mail_result)

                if (
                    login_count is not None
                    and money is not None
                    and has_new_mail is not None
                ):
                    status = "success"
                    message = "PTT 資料查詢完成"
                else:
                    status = "partial_success"
                    missing = []
                    if login_count is None:
                        missing.append("登入次數")
                    if money is None:
                        missing.append("P 幣")
                    if has_new_mail is None:
                        missing.append("站內信")
                    message = "無法解析：" + "、".join(missing)

            else:
                status = "partial_success"
                message = "PTT 登入成功，但無法取得使用者資料頁"
                session.event(message)

            logout_confirmed, logout_method = session.logout()

            if not logout_confirmed:
                session.event("未確認 PTT 正常登出，已關閉 SSH 連線")

    except KeyboardInterrupt:
        status = "failed"
        message = "程序被中斷"
        session.event(message)
        raise

    except Exception as exc:
        status = "failed"
        message = f"未預期錯誤：{type(exc).__name__}: {exc}"
        session.event(message)

    finally:
        debug_text = session.debug_text()
        session.close()

    record = {
        "status": status,
        "message": message,
        "account_index": account_config["index"],
        "account": account_config["account"],
        "account_label": account_config["label"],
        "ssh_user": "bbs",
        "ptt_host": HOST,
        "login_count": login_count,
        "money": money,
        "money_retry_attempted": money_retry_attempted,
        "money_retry_succeeded": money_retry_succeeded,
        "has_new_mail": has_new_mail,
        "last_login_ip": last_login_ip,
        "query_method": session.query_method,
        "two_factor_required": session.two_factor_required,
        "two_factor_verified": session.two_factor_verified,
        "two_factor_method": session.two_factor_method,
        "dec2026_seen": session.dec2026_seen,
        "dec2026_batches": session.dec2026_batches,
        "logout_confirmed": logout_confirmed,
        "logout_method": logout_method,
        "started_at": session.started_at,
        "finished_at": now(),
        "duration_seconds": round(time.monotonic() - session.started, 2),
        "events": session.events,
    }

    return record, debug_text


def aggregate_status(account_records):
    statuses = [item["status"] for item in account_records]

    if statuses and all(status == "success" for status in statuses):
        return "success"

    if any(status in {"success", "partial_success"} for status in statuses):
        return "partial_success"

    if statuses and all(status == "auth_failed" for status in statuses):
        return "auth_failed"

    return "failed"


# ============================================================
# Main
# ============================================================

account_records = []
debug_sections = []
interrupted = False

log(f"設定讀取完成，共 {len(ACCOUNT_CONFIGS)} 個 PTT 帳號")

try:
    for position, account_config in enumerate(ACCOUNT_CONFIGS, start=1):
        if position > 1 and ACCOUNT_DELAY > 0:
            log(f"帳號間隔等待 {ACCOUNT_DELAY:g} 秒")
            time.sleep(ACCOUNT_DELAY)

        record, debug_text = run_account(account_config)
        account_records.append(record)
        debug_sections.append(
            "#" * 72
            + "\n"
            + f"# ACCOUNT {position}: {account_config['label']} ({account_config['account']})\n"
            + "#" * 72
            + "\n\n"
            + debug_text
        )

except KeyboardInterrupt:
    interrupted = True
    log("程序被使用者中斷")

status = aggregate_status(account_records) if account_records else "failed"
success_count = sum(item["status"] == "success" for item in account_records)

if interrupted:
    status = "failed"
    message = "程序被中斷"
elif status == "success":
    message = f"{success_count}/{len(ACCOUNT_CONFIGS)} 個帳號查詢成功"
elif account_records:
    message = f"{success_count}/{len(ACCOUNT_CONFIGS)} 個帳號查詢成功"
else:
    message = "沒有完成任何帳號查詢"

record = {
    "status": status,
    "message": message,
    "account_count": len(ACCOUNT_CONFIGS),
    "processed_account_count": len(account_records),
    "success_count": success_count,
    "started_at": STARTED_AT,
    "finished_at": now(),
    "server_name": SERVER_NAME,
    "hostname": SERVER_NAME,
    "system_hostname": SYSTEM_HOSTNAME,
    "accounts": account_records,
}

# Preserve commonly used top-level fields in single-account mode.
if len(account_records) == 1:
    single = account_records[0]
    for key in (
        "account",
        "account_label",
        "login_count",
        "money",
        "money_retry_attempted",
        "money_retry_succeeded",
        "has_new_mail",
        "last_login_ip",
        "query_method",
        "two_factor_required",
        "two_factor_verified",
        "two_factor_method",
        "dec2026_seen",
        "dec2026_batches",
        "logout_confirmed",
        "logout_method",
        "events",
    ):
        record[key] = single.get(key)

combined_debug = "\n\n".join(debug_sections)

try:
    save_files(record, combined_debug)
    log(f"本機紀錄已寫入：{LOG_DIR}")
except Exception as exc:
    log(f"本機紀錄寫入失敗：{exc}")

telegram_ok, telegram_error = send_telegram(build_telegram(record))

if telegram_ok:
    log("Telegram 通知已成功發送")
else:
    log(f"Telegram 通知發送失敗：{telegram_error}")

print(json.dumps(record, ensure_ascii=False, indent=2))

if not telegram_ok:
    sys.exit(4)
if interrupted:
    sys.exit(1)
if status == "success":
    sys.exit(0)
if status == "partial_success":
    sys.exit(2)
if status == "auth_failed":
    sys.exit(3)
sys.exit(1)

PY
