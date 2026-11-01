# 本機 doctor 與 Azure 香港 Hysteria 2 實測

## Context

使用者希望一個指令診斷當前本機代理，並在 Hanru 的 Azure 帳號建立最低實用規格的香港 VM，試跑 Hysteria 2（HY2）後配置到本機。

目前沒有頂層 `doctor`；已有 `proxy status`、`diagnostics network`、`targets test`、目的地診斷，以及 Docker／analytics 的局部 doctor。新增的是唯讀總覽，不重寫這些診斷能力。Azure 建置、HY2 原生部署、獨立驗證及 client import 已存在，優先用現成流程，不新增一套部署工具。

### 已完成的唯讀調查

- Hanru 已自行登入；驗證身分為 `user@example.com`。
- 訂閱：`<AZURE_SUBSCRIPTION_ID>`；tenant：`<AZURE_TENANT_ID>`。後續每個 Azure 操作顯式指定此訂閱。
- Azure API 確認 `eastasia` = **Hong Kong**；Compute／Network／Storage providers 均 Registered。區域與相關 B-family CPU 配額各 20、目前使用 0；以下 SKU 無列出的訂閱限制，但這不保證實際配置容量。
- 本機 target `local-clash-verge-rev` 的 controller `127.0.0.1:9097` 可讀，Mihomo `v1.19.32`；mixed port 7897、rule mode、TUN `utun8` 啟用。macOS HTTP／HTTPS／SOCKS 均指向 `127.0.0.1:7897`；目前 process 沒有 proxy env。尚未驗證外網或 HY2。
- 全域預設 target 是遠端 `david-ubuntu`，不能把它當作本機。
- 安裝中的 lazyclash 是 `v0.1.12`，不同於目前 checkout；執行新功能與部署時使用從此 checkout 建置的獨立 binary，不直接覆寫 Homebrew 安裝。
- `~/.ssh/id_ed25519.pub` 指紋與目前 ssh-agent 中 Hanru 的 key 相符；不需新建 key，不讀取／輸出 private key。
- 未建立 VM、未部署服務、未修改本機代理；未執行測試。保留現有 `.specstory` 自動產生的未追蹤檔。

### 香港即時零售報價（2026-11-01 本地時間）

以下均含 32 GiB Standard SSD 與 Standard static IPv4，以每月 730 小時計，不扣訂閱 credit／共用免費額度：

| SKU | CPU / RAM | 固定 USD/月 |
| --- | --- | ---: |
| **Standard_B2pts_v2（推薦，ARM64）** | 2 vCPU / 1 GiB | **14.518** |
| Standard_B2ats_v2 | 2 vCPU / 1 GiB | 15.613 |
| Standard_B1s | 1 vCPU / 1 GiB | 16.708 |
| Standard_B2ts_v2 | 2 vCPU / 1 GiB | 16.708 |

推薦規格的 compute 8.468 + disk 2.40 + IPv4 3.65 = **約 US$14.52/月**。Deallocate 後 disk/IP 仍約 **US$6.05/月**；磁碟交易、稅及出站流量另計。第一個付費流量級距 US$0.12/GB；API 列出的 100 GB 是共用額度，不保證尚有可用餘額。0.5 GiB 的 B1ls 不符合現有部署選擇器最低 1 GiB 要求。這是已比較的相容小型 SKU 中最低價，不宣稱 Azure 所有 SKU 的絕對最低價。

## A. 新增 `lazyclash doctor`

### 互動與輸出契約

- 一次性 CLI：`lazyclash doctor`、`doctor --json`、`--target LOCAL doctor`、`--controller LOOPBACK doctor`；新增 `--timeout`，預設整體 10 秒。
- 預設本機、非互動、被動檢查。允許 controller GET 及本機 metadata；不發送外網測試、不呼叫 URLTest／healthcheck、不寫設定、不開 SSH、不啟動或修復服務，不改 TUN／系統代理／selector。
- 人類輸出為簡短分項檢查與具體下一步；JSON 為單一 typed report，含 schema version、scope、selection、checks、summary、建議。
- 項目狀態為 `pass / warn / fail / unknown / skip`。部分檢查失敗仍輸出其餘結果；明確標註「出口連通性未測試」。
- 退出碼：0 = 主要檢查完成且無 failure（允許 warning／可選 unknown）；1 = failure 或主要診斷未完成；2 = CLI 用法錯誤；130 = 取消。設定损壞屬診斷報告中的 failure，不在收集前直接退出。

### 實作步驟與關鍵檔案

1. **新增 `internal/doctor/run.go` 及測試**：共享聚合服務、typed report、可注入 collectors；避免放進 `diagnostics` 導致日後與 `managedcore` 循環引用。首版不整合服務 lifecycle，也不新增 TUI。
2. **設定與目標獨立處理**：使用 `config.Load`（`internal/config/config.go`），區別不存在的預設設定／明確指定檔案缺失／格式錯誤；環境與 OS 檢查不依赖設定載入成功。
   - 重用 `internal/proxyenv/resolve.go` 的 `IsLocalTarget`、local-default／單一候選／ambiguity 規則；必要時小幅抽取 selection 及 runtime endpoint helper，維持現有 `Resolve` 行為。
   - 分開 controller 身分與 data endpoint 的來源／優先序（包含 `LOCAL_PROXY_URL`），不能因 controller 離線就斷言代理 data path 故障。
   - 顯式遠端 target／SSH 不被偷換成本機：保留本機報告並標示 scope 不適用，不執行遠端連線。
3. **限制 discovery 在發送請求前只看本機**：在 `internal/connection/discovery.go` 增加可重用的 local-only 路徑，於 probe 前排除非 loopback／Unix candidates；保留既有 Discover 行為。不自動保存候選，不把零候選當成「沒有任何代理」。
4. **收集與判讀證據**：
   - 重用 `proxyenv.EnvironmentStatus`（`internal/proxyenv/probe.go`）取得已遮蔽的 process proxy variables。
   - 重用 `networkcheck.ReadSystemProxy`（`internal/networkcheck/system_proxy.go`）的 typed availability；macOS service 設定不代表每個 service 正在使用，unsupported 不等於 disabled。
   - 使用 `connection.Open(..., true)` 與一次 `/configs` snapshot 讀 controller identity、mode、ports、TUN；避免串接兩次 resolver／diagnostics.Test 重複請求。
   - 重用 `networkcheck.InspectWithOptions`（`internal/networkcheck/inspect.go`）的 capability 與必要介面／路由／DNS 證據，不搬入「新增 TUN 前」的整套 failure 判斷。
   - 比較同 scope 的 OS/env endpoint 與 runtime；不一致通常是 warning，不推定 ownership。TUN-only、無 proxy env、direct mode 本身均非故障。
   - 所有 collectors 有 bounded timeout／context cancellation，關閉 clients/helpers；不輸出 raw target、完整 config、PAC query、token、密碼或未遮蔽錯誤。
5. **新增 `internal/cli/doctor.go`**：薄 handler、human/JSON rendering；在 `internal/cli/root.go` 註冊並沿用既有 flag 驗證與 color/output 慣例。
   - `internal/cli/execute.go`／`root.go` 加窄範圍 typed reported outcome：報告成功輸出後才能帶非零 exit，不再印第二個 error envelope；其他命令退出與 error 契約不變。
6. **文件**：更新 `README.md`、`docs/diagnostics-and-routing.md`、必要的 embedded operating guide，説明 doctor 與主動測試的差別，以及現有 scoped doctors。

### 驗證

- Domain／CLI fixtures：正常、壞 TOML、缺設定、missing secret、401/403、offline、timeout、取消、多 target、default remote、explicit remote、IPv4/IPv6 loopback、Unix、TUN-only、缺 Python／unsupported OS backend。
- 安全契約：fake servers 限定本機只收到 GET version/configs；禁止 SSH、遠端 discovery、主動出口、mutating API、持久設定／session 寫入；env/config credentials 在 human/JSON 均遮蔽。
- 單一 JSON report、退出碼、writer error、help 無初始化；endpoint consistency 不錯判 TUN。
- `go test ./internal/doctor ./internal/cli ./internal/proxyenv ./internal/connection ./internal/networkcheck`；再 `go test ./...`，失敗如實報告。
- 建置 `./cmd/lazyclash` 到隔離的本機暫存位置；以新 binary 在這台 Mac 執行 human（PTY）及 JSON doctor，確認不改設定／selector／系統代理。保留 Homebrew binary。

## B. 用既有 az-backed 流程實測香港 HY2

### 1. 再預檢與建立付費 VM

- 使用新 binary，重新驗證上述 user／tenant／subscription、報價、quota、ARM Ubuntu image、inventory ID 不衝突。指定 `Standard_B2pts_v2`、Ubuntu 24.04 ARM64 的 pinned image、32 GiB disk、native backend；若缺容量或價格提高，停止回報，不自動升級機型或換區域／帳號。
- 以本機已載入的 `id_ed25519.pub` 作 SSH 公鑰。建立前辨識實際 SSH 管理路徑的出口 IPv4，將 TCP 22 限於該 `/32`；TUN／既有代理會影響出口，不能把任何 IP 查詢結果直接當實體網路出口。無法確定時請使用者提供管理 CIDR，絕不默認全網 SSH。
- 先 preview，再展示精確帳號、成本、資源、SSH CIDR、digest；取得**此階段付費資源核准**後才 apply：

```sh
$LC vps create azure-hk-hy2 --provider azure \
  --subscription <AZURE_SUBSCRIPTION_ID> \
  --region eastasia --plan Standard_B2pts_v2 --architecture arm64 \
  --disk-gb 32 --ssh-key "$HOME/.ssh/id_ed25519.pub" \
  --ssh-cidr "$ADMIN_CIDR" --json
# 以完全相同參數追加 --yes --expect "$VM_DIGEST"
```

- 使用 `internal/vps/azure*.go` 的既有 az adapter／owned resource group／operation receipts。只建立一台，不碰既有資源。現有 NSG 開 TCP 80/443 與 UDP 443；HY2 使用 UDP 443、ACME 使用 TCP 80，無需新增管理 UI、Bastion、NAT Gateway 或付費 DNS zone。
- 部分／不確定建立結果先 status/resume reconcile，不能重試建第二台。

### 2. DNS、SSH trust 與 HY2

- 推薦在**新 VM 所屬 public-IP resource**上透過 `az network public-ip update --dns-name ... --subscription ...` 設唯一 Azure DNS label，讀回真實 `dnsSettings.fqdn`（通常 `LABEL.eastasia.cloudapp.azure.com`）。不需購買 domain、不猜測 FQDN；驗證公開 A／AAAA 正確。
- DNS 名稱及公開憑證會公開（包含 Certificate Transparency），於部署審核中説明。若 Azure hostname 的 ACME 簽發受限，停止處理再選可控 hostname；不用 self-signed 或 skip-cert-verify 繞過。
- SSH host key 經 Azure 已驗證控制面／console 比對後才加入 known_hosts；不使用 `StrictHostKeyChecking=no` 或僅信任未驗證的 ssh-keyscan。
- 確認 Ubuntu 24.04、sudo -n、Python/systemd、port binding／防火牆／DNS／ACME 前提。沿用 `internal/serverdeploy` 預檢与 receipt：

```sh
$LC servers deploy hy2-hk --host azure-hk-hy2 \
  --recipe hysteria2 --backend native \
  --public-host "$VM_IP" --domain "$AZURE_FQDN" --obfs none --json
# 審核後，以相同參數追加 --yes --expect "$SERVER_DIGEST"
```

- 首次不加 obfuscation／進階調優。省略可選 ACME email，避免不必要個資登記。確認 certbot.timer 與 renewal hook；TCP 80 保持可供續期。
- `internal/serverprobe/probe.go` 既有 isolated Mihomo 必須得到 authenticated HTTPS 成功與觀察到的 VM 出口。不得只根據 systemd running 或 exit 0 宣稱成功；`installed-unverified` 要如實處理。
- 本機既有 TUN 可能造成巢狀代理：查看 routes，必要時用既有 `--verify-interface` 指定經確認的實體介面；不為測試關掉現在的代理。區分端到端 HY2 成功與「本機直接到香港」已證實。
- 只做少量功能請求，不做大流量 benchmark；網路擋 UDP 時保留具體證據，不盲目加大 VM。

### 3. 本機匯入，與切換流量分離

- 顯式 target `local-clash-verge-rev`，重查 `configs source show`、Verge 當前 profile UID 與 selector，不能只信舊 registration；source binding 不一致則先停止，不直接改生成的 runtime YAML。
- HY2 獨立驗證通過後，透過既有 `servers connect`／`configwork` preview source diff、backup／receipt。新建 `HY2-Test` 群組，不更動父群組、rules 或現在 selection：

```sh
$LC --target local-clash-verge-rev servers connect hy2-hk \
  --create-group HY2-Test --json
# 説明 reload 的影響並取得本機寫入核准，再追加 --yes --expect "$CLIENT_DIGEST"
$LC --target local-clash-verge-rev servers connect hy2-hk --verify --json
```

- 匯入可能 reload；不能承諾完全無流量影響。unowned Verge 若回 `persisted_pending_owner_reload`，由使用者在 Verge 重載正確 profile 再驗證，不擅自繞過 owner。
- 驗證節點存在、source/runtime 一致、憑證與 node test 成功；不自動切換目前主代理。使用者另行要求切流量時才審核目標群組／成員並保留原 selection。
- 最後用 doctor 再檢查本機狀態，回報 VM identity/IP/FQDN、server verification、匯入／activation 狀態及仍未驗證事項；不印 client credentials。

### 4. 回復與費用收尾

- 分別保留 VM、server、client 的 receipts／可恢復狀態；不能把 timeout 視為沒有寫入。
- Client 回復用 configwork 原生 restore／verify，不覆寫整份 Verge 設定。
- 預設保留已建立的 VM 供使用，清楚告知持續費用；不擅自刪除。使用者選擇刪除時，先移除本次 client/server 關聯，再按 owned-resource preview 刪除本次 VM/disk/IP，確認實際資源均消失；deallocate 不等於清零費用。
- 正式雲端操作前跑相關 `./internal/vps ./internal/serverdeploy ./internal/serverprobe ./internal/configwork ./internal/cli` 測試。付費香港 VM、ACME/systemd 與本機真實代理的驗收要分開記錄，unit tests 不能替代。

## 執行進度（持續更新）

### Closeout — 2026-11-01

- 使用者試用結束，明確要求刪除磁碟/IP並日後重建。已先移除hy2-hk服務，再經reviewed vps delete刪除整組香港VM/disk/IP/network；inventory deleted且Azure group exists=false。不是僅deallocate，也沒有保留本次billable資源。
- 本機維持Rule與David Azure (JP)；HY2-Test兩個節點仍保留在使用者profile，隨伺服器刪除已失效，未擅自再修改其Verge配置。
- 新分支feat/local-doctor-hk-closeout；commit 1fb66995579e9d2e07c24028c22752238884bc1b，31個產品檔案；沒有push。
- 使用dev git hygiene私有精準身分規則與secret scanner，review/apply redact兩個synthetic findings，再修正test/doc語意。最終staged scan complete、0 blocking、4 reviewed CIDR/test-IP warnings；go test ./...及go vet ./...通過。commit tree精確等於掃描tree，index為空。
- 新聊天與此raw plan仍untracked、未納入commit；沒有聲稱已停止SpecStory或對live artifact完成去敏。規則apply在其他Herdr pane被writer guard拒絕後，改由owner session完成，無override/bypass；scan/stage/固定index commit於另建pure shell pane完成。敏感原始值未回送到聊天。


- doctor 已實作完成，主要變更為 `internal/doctor/`、`internal/cli/doctor.go`、local-only discovery、shared selection 與 typed CLI outcome；文件及 fixtures 已更新。
- 完整 `go test ./...`、`go vet ./...`、focused race tests、`git diff --check` 全部通過；Windows amd64 交叉編譯成功。
- 真實 Mac JSON 與 human PTY doctor 通過：7 pass、1 warn、0 fail、exit 0。Ethernet 保存 7890 與目前 Wi-Fi/core 7897 不同，僅提醒不判失敗；出口未測試。
- 最新執行用 binary：`/private/tmp/lazyclash-hk-build.JV8LBE/lazyclash-current`；未覆寫 Homebrew binary。
- 已確認本機實體介面 `en1`、內網 `192.168.31.172`；以 curl 綁定 en1 的 AWS checkip 得 `112.87.208.29`。ipify 失敗、Cloudflare IP 直連 timeout；不把這些失敗當成 HY2 結果。
- VM preview image：`Canonical:ubuntu-24_04-lts:server-arm64:24.04.202610210`；SSH CIDR `112.87.208.29/32`；digest `22769bf07b205fc4887eb816f34745c0a1556277ee257a35fe646c2b6ebb5a0b`。
- 使用者已明確選擇「建立這台 VM」。首次 create 在唯讀 `az vm list-skus` 階段逾時；az shell 被殺後 Python 子程序仍持有 stdout，手動終止本次掛住的唯讀子程序後，CLI 正常回報 context deadline exceeded。重新查詢 Azure owned resources 與本機 VM inventory 均為空，未提交 VM。
- 已修正 `internal/vps`：Unix 使用獨立 process group 一起取消，所有平台加 bounded WaitDelay；explicit plan 使用 az --size 縮小序列化結果（CLI 端 substring filter，仍保留精確 SKU 校驗）。新增 timeout 與 filter 回歸測試並通過。
- 第二次 create 已建立專用網路，但 VM 提交被 Azure feature gate 拒絕：`securityType=Standard` 要求 `Microsoft.Compute/UseStandardSecurityType`，當前狀態 `NotRegistered`。Azure deployment `vm_deploy_M8NBHc1o8dAKWm5Bnve9IbePOn3UThcG` 已 Failed；查詢確認沒有 VM 或 disk。不得再呼叫 create；使用現存 operation 的 resume。
- 現存 operation：`lc-86fc4b0df41f338958b1d724`；resource group：`lc-86fc4b0df41f338958b1d724-rg`。已存在 VNet、NSG+rules、subnet、NIC、Standard static IPv4 `20.24.64.101`（public-IP resource `lc-86fc4b0df41f338958b1d724-ip`），IPv4 單價 US$0.005/h。這些資源均有本次 ownership receipt。
- 唯讀 resume preview digest：`466ffab672c0f77b80696fa6a64fdcde9ba2513c6900e9b450c927b4441ae726`（apply 前重查）；原配置與 US$14.518/月報價未變。
- 再查 SKU：B2pts_v2 的 `TrustedLaunchDisabled=True`；pinned Ubuntu image 雖支援 TrustedLaunch，但機型不支援。使用者改為授權「看看有什麼推薦的直接幫我建立」，並要求解釋兩種安全模式與手動操作。
- 已新增並測試 `--azure-security-type TrustedLaunch|Standard`：request/digest pinning、SKU/image preflight、Secure Boot/vTPM flags、post-provision verification。省略旗標保留 legacy Standard，不修改舊 journals。完整 tests/vet/Windows cross-build 再度通過。
- 推薦並成功建立 `azure-hk-hy2-tl`：B2ats_v2 / amd64 / 2 vCPU / 1 GiB / Ubuntu 24.04 server:24.04.202610210 / 32 GiB SSD / US$15.613 fixed monthly。操作 `lc-6424fc21f23859812e74bccc`；RG `lc-6424fc21f23859812e74bccc-rg`；VM `lc-6424fc21f23859812e74bccc-vm`；static IP `HK_PUBLIC_IP`。Azure show confirms Succeeded, TrustedLaunch, secureBootEnabled=true, vTpmEnabled=true。Standard feature 仍 NotRegistered，未修改。
- 新 VM preview digest `d0e55d4d89363047e91d3161396e5bf873027754a7136da2524154a6b291a819`。最新 binary `/private/tmp/lazyclash-hk-build.JV8LBE/lazyclash-trusted`。
- 已設定新 public-IP DNS label，FQDN `lc-hy2-hk-6424fc21.eastasia.cloudapp.azure.com`，A 正確指向 `HK_PUBLIC_IP`，無 AAAA。
- 使用者明確批准清理舊 ARM 失敗 RG；重新驗證只有四個本次 network resources 後執行精確 `az group delete`，背景任務 `bu7vi85ns` 尚待確認完成。CLI 原 operation 仍保守保留 unconfirmed，`resume --reconcile-only` 無法解除；不手改 journal。
- 舊 ARM RG 刪除已完成，`az group exists` 回 false；舊 public IPv4 已隨 RG 釋放。舊本機操作紀錄保留，不手改 journal。
- 新 VM SSH en1 direct TCP 22 持續 timeout。Azure RunCommand 已確認 ssh.socket active、0.0.0.0:22 listening，並取回 public host key；ED25519 fingerprint `SHA256:d6tNti/LOzq8xmrishzXSf+BPlW8+G7k1+DEwug+gKQ`，保存於本次 isolated known_hosts。Boot diagnostics 未启用，不為讀 key 開啟它。
- 本機當前 PROXY 重新取樣為 `David Azure (JP)`（不是早先 oracle；不是本次工具切換）；proxy egress 48.210.71.128。使用者明确批准此管理出口並繼續 HY2，已將 SSH NSG 白名單擴為 `112.87.208.29/32` 與 `48.210.71.128/32`，其他端口不變。NSG 傳播後 SSH 成功，guest 確認 SSH_CONNECTION source=48.210.71.128、x86_64、Ubuntu24.04、sudo -n 成功。
- SSH wrapper 已改為僅本次 host 使用 `nc -X connect -x 127.0.0.1:7897 -G 8 %h %p`，仍用独立 known_hosts，不更動日常 SSH／proxy 設定。
- HY2 native preview成功；server ID `hy2-hk`、host `azure-hk-hy2-tl`、UDP443、domain如上、Hysteria app/v2.13.0 artifact sha256 `907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691`、無 obfs、ACME無email。Deployment digest `d2a9aa71f33a52d31bea8e33dee2d1324529e567b40e5eace347edd1d6b3e7f6`。
- HY2 初次 apply 在 artifact 階段失敗：官方公共下載站對 Python urllib 預設 UA 回 403，truthful `lazyclash-server-deploy` UA 回 200。已修正固定 helper 並新增 regression（仍強制 SHA256／長度檢查），從既有憑證／token resume，未重生成部署。
- HY2 native service 與 certbot.timer active、UDP443 listening。憑證 CN 為該 Azure FQDN，Let's Encrypt YE2，2026-10-31 至 2027-01-29 有效；VM 出口HK_PUBLIC_IP，兩個 verification endpoints從VM均HTTP200。
- `--verify-interface en1` 的獨立client測試失敗，HTTP proxy local auth正常，HY2 dial deadline。未指定介面、沿用現有TUN路徑則認證HTTPS成功，出口HK_PUBLIC_IP；伺服器只輸出safe addr欄位確認來源48.210.71.128，證明是日本→香港鏈路，而非實體直連。
- 已用正常 CLI resume 成功紀錄 server ready（action digest ddbc1f6ec579ca38e9a61cb7cbe68cfb2443d4114cbfd61ca5421b92c1b78c38）；live status的成功verification scope需解釋為當時current route。最新 binary `/private/tmp/lazyclash-hk-build.JV8LBE/lazyclash-hy2`。
- 使用者明確要求「獨立測試節點 + 日本→香港鏈路兩邊都放測試」，已將兩節點透過 `proxies import` 匯入local profile `Personal proxies (lazyclash)`/UID LGz0xjOfr4vD，群組 HY2-Test。`hy2-hk` 為原生；`hy2-hk-via-jp` 的 dialer-proxy 固定 `David Azure (JP)`（不指向PROXY群組，避免循環）。為補償Verge自動selector插入，保留同內容PROXY local override；事前已說明。
- Import digest `6d9616e600d706734266627fade9e4d457c5120563bb4c5fb3a875f54666be1c`；receipt `43f1a835b558eb980a3f93f1229a625f`。使用者已在Verge手動重載並貼圖。`configs verify` 現為 source_and_structure_verified，source/generated/runtime三者確認；PROXY仍David Azure (JP)、Final仍PROXY，兩節點不在主PROXY成員中。
- 真實 core node test：hy2-hk HTTP504/Timeout；hy2-hk-via-jp 成功146ms（使用者GUI先前158ms）。服務端25秒tcpdump僅看本次兩來源UDP443封包headers：112.87.208.29去程擷取10筆、VM回送21筆；48.210.71.128去程21筆、回送26筆（可能含抓包重複，不推算丟包率）。因此去程確實到VM、VM有回應，不是SSH白名單誤套到HY2；不能由此斷言GFW，還需Mac收包/回程證據。
- Azure effective NSG證明UDP443對0.0.0.0/0開放並套用NIC/subnet；SSH22只限批准兩個/32。額外adminNetworkSecurityGroup只有特定IPv6 outbound deny，與本次IPv4無關。Guest UFW inactive、iptables INPUT/OUTPUT ACCEPT、bindv6only=0。
- Mac `sudo -n true` 回 password required；`! sudo -v` 也因無互動TTY失敗，不能依靠此方式取得sudo。已更正為使用者在獨立Terminal自行執行目標限定tcpdump（不改sudoers、不傳密碼）；user capture file `/tmp/lazyclash-hy2-client.i6pCzw`，sudo權限並未授予本session其他命令。
- 2026-11-01 04:38 +08:00 同步Mac en1／VM eth0擷取，精確同flow source port64646：Mac10筆送出、0筆收到；VM10筆收到、22筆回送（含37/91-byte小UDP回包，筆數可能有抓包重複，非丟包率統計）。讀取完整Mac文字記錄確認只有去程，沒有漏掉其他格式回包。direct core test仍HTTP504；hy2-hk-via-jp成功139ms。
- 額外驗證Azure outbound effective rules：IPv4 AllowInternetOutBound priority65001先於DenyAll65500；唯一admin deny僅特定IPv6，guest OUTPUT ACCEPT。配置白名單不是此HY2問題。觀察將問題縮至VM送出至Mac en1收包之間，但不能只由這些觀察分辨GFW／ISP／家用路由器NAT／其他回程網路過濾；沒有證明特定攔截者。單純MTU過大不足解釋小回包同樣消失。
- 已告知使用者此輪結束、可Ctrl+C停止其Terminal tcpdump；不宣称替使用者停止了程序。使用者最新目標改為臨時對外HK，明確暫停直連除錯，要求保存pitfall；未探索項不再執行。
- 已新增 `pitfalls/README.md` 與 `pitfalls/hysteria2-direct-timeout-return-udp.md`，README有入口；保留錯誤原文、雙端證據、未知根因、暫停下一步與workaround。既有TODO格式非harness lane格式，未為單一記錄強制遷移或新增AGENTS指令。
- 本次地區驗證：以當前Verge日本路由→獨立localhost HY2 client實際HTTPS請求，IP.SB回HK_PUBLIC_IP、Hong Kong/HK/Kowloon/Microsoft Azure/Asia-Hong_Kong；Cloudflare回同IP、loc=HK、colo=HKG。額外兩節點source-export + en1獨立測試曾curl35，沒有拿來當成功證據也不擴大調查。
- 主PROXY仍David Azure (JP)；GLOBAL目前也選David Azure (JP)，其成員已含hy2-hk-via-jp。沒有為地區驗證更動live routing。若使用者需臨時所有經core流量走HK，可於Verge Global模式選GLOBAL成員hy2-hk-via-jp，用完恢復Rule；不能宣稱僅新增測試群組就已讓一般流量變HK。
- 地區驗證的私有export／client config／curl auth副本已清除，獨立client已停止。
- 診斷暫存 Go test已移除；私有暫存 node.yaml/test-nodes.json已清除。正式node只留在private server journal與已核對Verge配置／backup。完整go test/vet、diff check與最後Windows cross-build通過；實體直連live test失敗另列，不當成unit成功。doctor最終仍7pass/1warn/0fail，TUN/主代理未改；未commit/push。
- 本次隔離 SSH wrapper：`/private/tmp/lazyclash-hk-ssh.hnTxII/ssh`。用 `LC_HK_SSH_TARGET=ubuntu@VM_IP` 與 PATH 前綴指定，只對此 host 加 `nc -b en1`、指定 id_ed25519 與獨立 known_hosts；尚未建立 host trust 或連接任何新 VM。
- Client source inspect 成功，綁定 profile `LGz0xjOfr4vD`；目前 `PROXY=oracle-sg-reality`、`Final=PROXY`，不要自動改選。該現有節點 runtime `udp=false`，HY2 verifier 使用 `--verify-interface en1`。

## 來源

- 報價：當次 `lazyclash --read-only vps quote`，底層 [Azure Retail Prices API](https://prices.azure.com/api/retail/prices)。
- Azure DNS label：[Microsoft Learn — Public IP addresses / Domain Name Label](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses#domain-name-label)。
- 現成流程與限制：`docs/server-deployment.md`、`docs/proxies-and-groups.md`、`internal/vps/azure_resources.go`、`internal/serverdeploy/service.go`、`internal/cli/server_connect.go`。
