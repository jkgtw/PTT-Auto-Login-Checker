# PTT Auto Login Checker

使用 PTT 官方 SSH 入口，依序登入一個或多個自己的 PTT 帳號，查詢登入次數、精確 P 幣、站內信狀態與上次登入位置，完成後正常登出，最後整合成 Telegram 通知。

本專案是終端機自動化腳本，不是 PTT 官方專案，也不使用 PTT 帳號資料庫或非公開 API。

## 功能

- 支援 **1～10 個 PTT 帳號**，同一支腳本依序執行，不會同時建立多個 PTT session。
- 使用 `ssh bbs@ptt.cc`，再於 PTT 登入畫面輸入各帳號 ID / 密碼。
- 自動執行 `Talk → Query → 自己的 ID`。
- 每個帳號取得：
  - 登入次數
  - 精確 P 幣（PTT 有輸出 `($數字)` 時）
  - 是否有未讀站內信
  - 上次登入位置
- 每個帳號可獨立設定 PTT 2FA：
  - 6 位 TOTP
  - 8 位救援碼
- 支援 PTT 2026-09-20 上線的 **DEC 2026 Synchronized Output**。
- 相容一般 ECMA-48 CSI escape sequence，降低新版控制碼污染文字解析的風險。
- P 幣尚未出現在自我 Query 頁時，可分段等待後自動重查。
- 多帳號結果合併成一則 Telegram HTML 通知。
- 可自訂 Telegram 顯示的 `SERVER_NAME`。
- 防止同一台主機重複執行腳本。
- 保存 `last.json`、`history.jsonl`、`last-debug.txt`。
- `history.jsonl` 自動輪替，避免無限增長。
- Debug log 會遮蔽密碼、TOTP secret、救援碼與實際送出的 2FA code。

## 執行環境

腳本只使用 Python 標準函式庫，不需要 `pip install`。

需求：

- Linux 或 macOS
- POSIX `sh`
- `ssh`
- Python 3

Ubuntu / Debian：

```bash
sudo apt update
sudo apt install openssh-client python3
```

macOS 通常已內建 `ssh`；Python 3 可透過 Homebrew 安裝：

```bash
brew install python
```

## 安裝

```bash
git clone <your-repository-url>
cd <repository-directory>
cp .env.example .ptt-check.env
chmod 600 .ptt-check.env
chmod 700 ptt-check.sh
```

編輯設定檔：

```bash
nano .ptt-check.env
```

腳本預設會讀取 **與 `ptt-check.sh` 同一目錄**的 `.ptt-check.env`。

也可以指定其他設定檔：

```bash
PTT_CHECK_CONFIG='/path/to/.ptt-check.env' ./ptt-check.sh
```

測試：

```bash
./ptt-check.sh
```

## 多帳號設定

推薦使用編號格式。

```bash
PTT_ACCOUNT_COUNT='2'

PTT_ACCOUNT_1='your_ptt_id_1'
PTT_PASSWORD_1='your_ptt_password_1'
PTT_ACCOUNT_LABEL_1='Main'
PTT_TOTP_SECRET_1=''
PTT_2FA_RECOVERY_CODE_1=''

PTT_ACCOUNT_2='your_ptt_id_2'
PTT_PASSWORD_2='your_ptt_password_2'
PTT_ACCOUNT_LABEL_2='Alt'
PTT_TOTP_SECRET_2=''
PTT_2FA_RECOVERY_CODE_2=''
```

最多支援 10 個帳號：

```text
PTT_ACCOUNT_1 ... PTT_ACCOUNT_10
PTT_PASSWORD_1 ... PTT_PASSWORD_10
```

`PTT_ACCOUNT_LABEL_n` 只是方便辨識的名稱，不會送給 PTT，可省略。省略後直接使用 PTT ID。

如果沒有設定 `PTT_ACCOUNT_COUNT`，但存在 `PTT_ACCOUNT_1`，腳本也可以由 1 開始自動偵測連續帳號；公開範例仍建議明確設定 `PTT_ACCOUNT_COUNT`，比較容易發現漏掉某組設定。

### 帳號間隔

所有帳號都是**依序執行**：第一個帳號完整登入、Query、登出後，才處理下一個帳號。

預設帳號間隔：

```bash
PTT_ACCOUNT_DELAY='1'
```

也就是兩個帳號之間等待 1 秒，避免短時間內連續建立大量登入連線。

## 舊版單帳號格式

仍支援舊設定，不需要立即改成編號格式：

```bash
PTT_ACCOUNT='your_ptt_id'
PTT_PASSWORD='your_ptt_password'
PTT_ACCOUNT_LABEL='Main'
PTT_TOTP_SECRET=''
PTT_2FA_RECOVERY_CODE=''
```

使用舊格式時，請不要同時設定 `PTT_ACCOUNT_COUNT` / `PTT_ACCOUNT_1` 等多帳號變數。

## PTT 2FA

每個帳號可以有自己的 TOTP secret：

```bash
PTT_TOTP_SECRET_1='YOUR_BASE32_SECRET'
PTT_TOTP_SECRET_2='ANOTHER_BASE32_SECRET'
```

腳本使用 PTT 目前的 TOTP 格式，在本機產生驗證碼：

- Base32 secret
- HMAC-SHA1
- 30 秒週期
- 6 位數字

如果帳號沒有啟用 2FA，保持空白即可。

救援碼：

```bash
PTT_2FA_RECOVERY_CODE_1='12345678'
```

建議以 TOTP 為主。救援碼可能是一次性資料；使用後應更新 `.ptt-check.env`。

腳本端最大嘗試次數是全域設定：

```bash
PTT_2FA_MAX_ATTEMPTS='2'
```

如果 PTT 帳號設定為「僅新 IP 需要 2FA」，而 PTT 判定目前來源不需要再次驗證，腳本不會看到 2FA prompt，這是正常情況。

## P 幣重查

PTT 的 self Query 有時會先顯示：

```text
《經濟狀況》家徒四壁
《目前動態》不在站上
```

但暫時沒有精確金額：

```text
($12345)
```

這通常是登入 session 尚未及時反映在線上使用者資料中。

預設設定：

```bash
PTT_MONEY_RETRY_DELAYS='1,2'
```

流程：

```text
第一次立即 Query
  ↓ 沒有精確 P 幣
等待 1 秒
  ↓ 再 Query
仍沒有
  ↓ 等待 2 秒
第三次 Query
```

如果第一次已取得 P 幣，不會增加額外等待。

最多接受三個 retry delay，例如：

```bash
PTT_MONEY_RETRY_DELAYS='1,2,4'
```

## DEC 2026 / ECMA-48

PTT 在 2026-09-20 於 PTT1 上線 DEC 2026 Synchronized Output，終端輸出可能被包在：

```text
ESC[?2026h
...一批畫面更新...
ESC[?2026l
```

腳本會追蹤這兩個控制碼。在 synchronized output 尚未結束時，`wait_for()` 不會根據半完成畫面做狀態判斷，收到結束控制碼後才繼續解析。

同時使用 ECMA-48 CSI pattern 清理終端控制碼：

```regex
\x1B\[[0-?]*[ -/]*[@-~]
```

每個帳號的 JSON 結果都包含：

```json
{
  "dec2026_seen": true,
  "dec2026_batches": 12
}
```

相關 PTT 說明：

- https://www.ptt.cc/bbs/PttCurrent/M.1789835193.A.E46.html
- https://www.ptt.cc/bbs/PttCurrent/M.1789835163.A.633.html
- https://github.com/ptt/pttbbs

## Telegram

必要設定：

```bash
TELEGRAM_BOT_TOKEN='123456789:YOUR_TOKEN'
TELEGRAM_CHAT_ID='123456789'
```

Telegram Topic / Forum thread 可選：

```bash
TELEGRAM_MESSAGE_THREAD_ID='123'
```

自訂執行主機：

```bash
SERVER_NAME='CloudFlare'
```

沒設定時使用 OS hostname。

### 單帳號通知

```text
#PTTAutoLogin

✅ 狀態：成功
👤 帳號：abc112233
📊 登入次數：1234
💰 P 幣：12,345
✉️ 站內信：📭 沒有新信
🌐 上次登入位置：1.1.1.1
🖥 執行主機：CloudFlare
```

### 多帳號通知

多帳號只會送出**一則整合通知**：

```text
#PTTAutoLogin

⚠️ 整體狀態：部分成功（1/2 成功）

── 帳號 1 ──
✅ 狀態：成功
👤 帳號：abc112233（Main）
📊 登入次數：1234
💰 P 幣：12,345
✉️ 站內信：📭 沒有新信
🌐 上次登入位置：1.1.1.1

── 帳號 2 ──
⛔️ 狀態：驗證失敗
👤 帳號：another_id（Alt）
📊 登入次數：未取得
💰 P 幣：未取得
✉️ 站內信：❔ 未取得
🌐 上次登入位置：未取得

🖥 執行主機：Oracle Cloud JP
```

如果某一個帳號失敗，腳本會繼續處理後續帳號，不會因單一帳號失敗就停止整批任務。

## 本機紀錄

預設每次執行寫入：

```text
last.json
history.jsonl
last-debug.txt
```

### `last.json`

只保留最近一次執行結果。

多帳號格式的主要結構：

```json
{
  "status": "success",
  "account_count": 2,
  "processed_account_count": 2,
  "success_count": 2,
  "server_name": "CloudFlare",
  "accounts": [
    {
      "account": "account1",
      "account_label": "Main",
      "status": "success",
      "login_count": 1234,
      "money": 12345,
      "has_new_mail": false
    },
    {
      "account": "account2",
      "account_label": "Alt",
      "status": "success"
    }
  ]
}
```

如果只有一個帳號，腳本另外保留常用的舊版 top-level 欄位，例如 `account`、`login_count`、`money`、`has_new_mail`，方便既有流程相容。

### `history.jsonl`

每次**整批執行**追加一行 JSON，而不是每個帳號各自一行。

預設：

```bash
PTT_HISTORY_MAX_MB='10'
PTT_HISTORY_KEEP_MB='5'
```

當檔案超過 10 MiB 時，會保留最新約 5 MiB，而且從完整 JSONL 行開始，不會從 JSON 中間切斷。

### `last-debug.txt`

包含本次所有帳號的 terminal debug，每個帳號之間有明確分隔。

預設最大：

```bash
PTT_DEBUG_MAX_MB='2'
```

Debug 會遮蔽：

- PTT 密碼
- TOTP Base32 secret
- recovery code
- 實際送出的 TOTP code

## Cron

例如每天 06:00：

```cron
0 6 * * * /home/ubuntu/dockerdata/autoptt/ptt-check.sh >> /home/ubuntu/dockerdata/autoptt/cron.log 2>&1
```

如果 cron 的系統時區不是台北，可依環境設定：

```cron
CRON_TZ=Asia/Taipei
0 6 * * * /home/ubuntu/dockerdata/autoptt/ptt-check.sh >> /home/ubuntu/dockerdata/autoptt/cron.log 2>&1
```

## Exit code

| Code | 意義 |
|---:|---|
| `0` | 全部帳號成功 |
| `1` | 執行失敗 / 被中斷 |
| `2` | 部分成功，或至少一個帳號取得部分資料 |
| `3` | 所有已處理帳號皆為驗證失敗 |
| `4` | Telegram 通知失敗 |
| `64` | `.env` / 設定錯誤 |
| `75` | 已有另一個腳本 instance 執行中 |
| `127` | 找不到 `ssh` 或 `python3` |

注意：多帳號模式只要不是全部成功，exit code 就不會是 `0`。這對 cron / systemd 健康監控比較有用。

## 安全建議

`.ptt-check.env` 可能包含：

- PTT 帳號密碼
- TOTP secret
- recovery code
- Telegram Bot Token

因此必須：

```bash
chmod 600 .ptt-check.env
```

## Dry run Telegram

如果只想確認 Telegram 訊息內容，不送出 API：

```bash
TELEGRAM_DRY_RUN='1'
```

注意：這只停用 Telegram API；PTT 登入與 Query 流程仍會實際執行。

## 除錯

如果腳本突然因 PTT 改版失敗，優先查看：

```bash
cat last.json
less last-debug.txt
```

以及 console / cron log。

常見原因：

1. PTT 修改登入 / 2FA 提示文字。
2. Talk / Query 選單或快捷鍵改動。
3. PTT 新增終端控制碼或 synchronized output 行為。
4. 線上使用者 cache 尚未同步，導致精確 P 幣暫時不顯示。
5. SSH / 網路無法連線到 `ptt.cc:22`。
6. 主機系統時間錯誤，導致 TOTP 失敗。

## License / disclaimer

此腳本是非官方個人工具。使用者應自行保管帳號憑證並遵守 PTT 的相關規範。PTT 畫面、登入流程與終端協定都可能變動，因此自動化流程未來可能需要隨站方更新調整。
