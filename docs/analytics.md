# 歷史流量分析與異常定位

Analytics 是明確啟用的背景收集器，資料保存在收集主機的私有 SQLite。
它與 Overview 的 15 分鐘記憶體圖表、目前 Connections、Logs 和雲端帳務查詢分開。
查詢不會開始收集，關閉 TUI 也不會停止已啟動的 collector。

## 開始收集

先在 core 所在主機註冊本地 target。收集器沿用該主機的 secret references，
不會把筆電上的秘密檔案路徑移植到 VPS，也不會替 SSH target 長期開啟筆電隧道。

```sh
lazyclash --target desktop analytics setup --source desktop --kind mihomo
# 檢查上面的預覽；--yes 保存，--enabled 明確啟用。
lazyclash --target desktop analytics setup --source desktop --kind mihomo --enabled --yes
lazyclash analytics doctor --json
lazyclash analytics collect --duration 10m
lazyclash analytics report --period week --group-by domain
lazyclash analytics report --interactive
```

裸 `analytics setup` 在互動終端開啟表單；完整 flags 適用自動化。
Dashboard `:` → **Historical analytics** 開啟同一個瀏覽器；
**Configure historical analytics collection** 使用相同設定表單。

Linux VPS 的網卡、access log 與 Stats 可分別註冊為來源：

```sh
lazyclash analytics setup --source vps-net --kind interface --interface ens3 --enabled --yes
lazyclash analytics setup --source proxy-access --kind xray-access \
  --path /absolute/readable/access.log --source-timezone UTC --enabled --yes
lazyclash analytics setup --source proxy-users --kind xray-stats \
  --binary /absolute/path/xray --address 127.0.0.1:10085 --enabled --yes
```

以上網卡、路徑及 API 位址都是範例，應從 `doctor` 與實際配置確認。`--server-id`、
`--host-id` 可附加 inventory 關聯，但不代表帳號或流量已可靠對應到人。
V2Ray Stats 使用 `--format v2ray`，core 必須提供相容的 JSON stats 命令。
沒有時區欄位的 access log 依 `--source-timezone` 解讀，預設使用 collector 主機
本地時區；這與報表的分析日界時區分開。舊版 v2ctl 可明確使用 `--format v2ctl`。
缺少權限、access log 或 stats policy 時會顯示 unavailable；安裝 collector 不會
啟用 core 的 telemetry、更換 UUID、加群組、修改防火牆或執行 sudo。

## 解讀數字

| 來源 | 可用資料 | 限制 |
|---|---|---|
| Mihomo | 網域／目的 IP、來源 IP、程式、inbound user、規則／代理鏈、觀測 bytes | 即時快照會漏短連線或最終 bytes；只看經該 core 的流量 |
| Xray／V2Ray access | accepted 連線事件、來源 IP、目的網域／IP、email／路由標籤 | 不包含每條連線的 bytes 或實際人的使用時間 |
| Xray／V2Ray Stats | 依 configured email 分組的 user counters | 共享憑證仍是同一帳號，沒有 user × domain bytes |
| Linux interface／vnStat | 主機介面 RX／TX | 包含 proxy 以外的服务；不同於雲端帳務 meter |

來源各自列出，絕不把同一批 client、server 和網卡 bytes 相加。頻率是觀測連線
事件數，不是網頁瀏覽次數；活躍分鐘是觀測到 bytes 增量的分鐘，不是螢幕時間。
Unknown／unattributed、漏樣、失敗與 partial coverage 不能解讀為零流量。
沒有 hostname 的目的 IP 保留為 IP，不會以 reverse DNS 猜網站。

第一次看到既有計數器先建立 baseline。持續觀測的連線按取樣區間增量記錄，
跨分鐘／日界依區間時間比例估計分配；core reset 或失聯區間不假裝可精確歸因。
分鐘報表使用完整可用分鐘 buckets；只剩每日資料時不虛構分鐘明細。

## 時間、retention 與資源限制

預設時區為 `Asia/Shanghai`，週一為一週起點；資料時間以 UTC 儲存。
`--from` 含起點、`--to` 不含終點，接受 YYYY-MM-DD 或 RFC3339：

```sh
lazyclash analytics report --from 2026-09-01 --to 2026-10-01 \
  --source desktop --group-by route --json
lazyclash analytics setup --detail-days 30 --minute-days 90 --day-months 13 \
  --max-mib 1024 --yes
```

來源預設 disabled；手動啟用後記錄明細。`setup --source ID --enabled=false --yes`
保存停用配置，重啟正在執行的 collector 後生效。設定可更改 polling 秒數；
預設 Mihomo／access 2 秒、Stats 15 秒、Linux 網卡 30 秒。

預設明細 30 天、分鐘彙總 90 天、每日彙總 13 月，資料目錄預算 1 GiB。
容量優先於時間期限；清理先明細、再分鐘、最後每日資料。狀態顯示實際最舊
保留時間與壓力／漏資料，不承諾任意流量下仍保留完整期限。取樣、讀入長度、
事件批次、report rows 和資料庫交易皆有界限，不保存每秒完整 JSON。

清理在 collector 執行時進行，停止服務後不會由查詢偷偷刪除資料。SQLite 使用
短交易與有空間預留的 rollback journal；資料預算也計入服務 executable、health
和 lock 檔。壓力期間先移除舊資料，再嘗試只保留未歸因的計數器總量；仍無空間時
保留可寫入的 health 狀態並標示缺口。

2026-09-22 的 Apple M4／macOS arm64 合成測試中，持久化 1,000 個不同維度的
access events 平均約 45 ms，10,000 個約 426 ms（各 3 次）。這只量測 SQLite
寫入，不包含實機 core、SSH 或整體 proxy throughput；可用
`go test ./internal/analytics -run '^$' -bench '^BenchmarkIngest' -benchtime=3x -benchmem`
重現。實際 collector 的 CPU 累積時間、heap、peak RSS、取樣延遲與漏樣在
`analytics status --json` 的 `collector` 中查看。

`analytics status` 讀取已保存狀態；`analytics doctor` 主動檢查已啟用來源和 user
service 能力。Report 只查本機資料庫或遠端 collector，不連線探測網站。
收集開始後不要直接改分析時區：已保存的日 buckets 不會被重新解讀；需要另一
時區的原生日資料時，使用獨立 config／state。查詢顯示時區可另行指定。

## 使用者服務與 SSH

```sh
lazyclash analytics service install
# 閱讀預覽後，以其 digest 套用；install 不會立刻 start。
lazyclash analytics service install --yes --expect REVIEWED_DIGEST
lazyclash analytics service start
lazyclash analytics service start --yes --expect REVIEWED_DIGEST
lazyclash analytics service status --json
lazyclash analytics --collector-host VPS_ALIAS report --period month --json
```

遠端需要已安裝支援 analytics 的 lazyclash 和 Python 3；可指定 `--remote-binary`。
加上 `report --also-host VPS_ALIAS` 可並列本機與遠端的歷史；可重複指定，最多
八個 collector，同時最多四個讀取。額外主機使用各自預設 analytics config／state，
額外的 `local` 表示本機。跨主機列以 `local::source`／`ssh/ALIAS::source` 區分，
逐層展開仍保留這個來源；離線主機顯示 unavailable／partial，不補零或合併用量。
`--collector-host` 下的設定、state、secret references 都在遠端解讀。
互動 report 留在本機；遠端 setup 使用完整 flags。
`--analytics-config` 選擇另一份 TOML，`--state-dir` 明確選擇資料位置。
不同自訂 config 預設分開 state；遠端查詢不複製正在寫入的 SQLite 檔案。

Linux 使用 systemd user service，沒有現成 linger 時只能依使用者 session 生存。
macOS LaunchAgent 依 GUI login session；休眠／關機期間無法收集。
工具不自動提權或改登入政策。stop／remove 也先預覽；remove 只移除擁有的服務
與私有 executable，保留配置及分析資料。檔案被外部修改時拒絕以舊 ownership 刪除。

## vnStat 歷史與通知

```sh
lazyclash analytics --analytics-config /private/path/vnstat-utc.toml setup \
  --source previous-net --kind vnstat --interface ens3 --timezone UTC --enabled --yes
vnstat --json d -i ens3 > /private/path/vnstat.json
lazyclash analytics --analytics-config /private/path/vnstat-utc.toml import-vnstat \
  --source previous-net --file /private/path/vnstat.json
lazyclash analytics alerts list --json
```

只匯入 JSON 中真實存在、已完成的日 buckets，保留原生時區；不從月總量推導
日／分鐘分佈，重複匯入不可重複累計。native day 與 collector 時區不相容時拒絕
匯入。主機歷史另保留來源，避免與即時網卡取樣混算。舊 log／vnStat 仍受各自
的外部 retention 限制，analytics 無法復原已不存在的網站紀錄。

每日 TX 告警預設門檻為 20／50／100 GiB，但通知預設關閉。以
`setup --alerts-enabled --webhook-file /absolute/private/webhook --yes` 明確啟用；
也可用 `--webhook-env`。秘密值不進 TOML、argv 或報表。只對 host interface／
vnStat 來源計量；同日跨過多級只產生最高等級，之後不補報較低等級。
發送狀態與退避重試會保存；网络 timeout 的 delivery result 可能不確定，
Discord 不提供此工作流的 exactly-once 保證。

切換現有 alert timer 前，應先比較相同介面、時區、單位的結果，再停用舊 timer。
GiB 是 1024³ bytes；網卡 bytes 不是帳單，費用請另外看 `vps usage`／`servers usage`。

## 規則診斷與身分管理

瀏覽器按代理流量／網域提供調查線索；選擇網域後明確執行診斷，並選對 client
target。大流量不能單獨證明該網域應直連；結果也不會自動改 selector 或 rules。
使用現有 `diagnostics url … --via POLICY` 比較後，再以 `rules add-domain` 的
預覽／套用流程修改。IP-only 行不自動猜 domain 或產生 suffix 規則。

每人／每裝置多 UUID、發放／收回／輪替另見
[憑證生命週期 backlog](../backlog/server-client-identities.md)。
