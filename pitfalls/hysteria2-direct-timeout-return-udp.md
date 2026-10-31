# HY2 直連 Timeout，但日本→香港鏈路成功

**Symptoms**: Hysteria2 / HY2、Timeout、HTTP 504、`installed-unverified`、`context deadline exceeded`、UDP 回程看不到封包、GFW / IP block / whitelist。

**First seen**: 2026-11-01。

**Affects**: 本次環境為 macOS、Clash Verge Rev 2.5.2／Mihomo v1.19.32（TUN 已啟用），Azure 香港 `eastasia`、Ubuntu 24.04、Hysteria `app/v2.13.0` 原生 systemd。這是此網路路徑的觀察，不宣稱所有版本／ISP 都有問題。

**Status**: workaround 已驗證；直連根因未確認、暫停調查。使用者當前只需要臨時香港出口，不再擴大直連除錯。

**Closeout**: 2026-11-01 臨時測試結束後，依使用者要求移除 HY2 服務並刪除 VM、磁碟、public IP 與專用網路，已確認資源群組不存在。既有測試節點因此失效；日後需重新建立資源、驗證新的 host key／憑證並更新 client endpoint，不可盲目重用舊 IP。

## Symptom

在當前本機的兩個獨立測試節點上：

```sh
# 以實際本機 target／節點名稱替換；這會發出主動測試流量，但不切換 selector。
lazyclash --target local-clash-verge-rev proxies delay hy2-hk --json
lazyclash --target local-clash-verge-rev proxies delay hy2-hk-via-jp --json
```

直連節點的 CLI 錯誤原文：

```json
{"error":{"code":"rejected","message":"test proxy latency: controller rejected the operation or read-back did not match (HTTP 504)","operation":"test proxy latency","http_status":504}}
```

獨立 Mihomo client 綁定實體介面 `en1` 時也失敗：

```text
authenticated proxy HTTPS verification failed at the configured endpoints; server remains installed but unverified
```

client 日誌中的錯誤文字：

```text
error: context deadline exceeded
```

日本→香港節點成功，當次不同輪測得約 139–158 ms。此數字是節點延遲測試，不是吞吐量或長期 SLA。

## Root cause — 尚未確定

**不要把這個案例標成「已證實 GFW 封鎖 IP」。** 已定位到回程未在 Mac 實體網卡被觀察到，但沒有定位到攔截設備／業者。

### 已確認的證據

1. 香港 VM、HY2 systemd service、UDP 443 listener 與 certbot renewal timer 正常；公開 TLS 憑證有效。
2. 經日本路由的完整 HY2 認證／HTTPS 測試成功，觀察到香港 VM 的 public IPv4；server connection 記錄確認來源為日本節點，而非本機實體出口。
3. 直接從 VM 訪問兩個 verification endpoints 均得到 HTTP 200，因此不是測試網站一律拒絕這台 VM。
4. Azure **effective NSG**（不是只看宣告設定）確認：
   - TCP 22 的 `/32` SSH 管理白名單，不適用於 HY2。
   - UDP 443 對 `0.0.0.0/0` 開放，已套用 NIC／subnet。
   - IPv4 `AllowInternetOutBound` 先於預設 deny。
   - 額外 admin rule 僅限制特定 IPv6 出站目的地，與此 IPv4 連線無關。
5. Guest UFW inactive、iptables INPUT／OUTPUT ACCEPT、`net.ipv6.bindv6only=0`。
6. **2026-11-01 04:38 +08:00 的同一條 UDP flow，Mac `en1` 與 VM `eth0` 同步擷取：**

   | 觀察點 | 本機→VM | VM→本機 |
   | --- | ---: | ---: |
   | Mac `en1` | 10 筆送出 | 0 筆收到 |
   | VM `eth0` | 10 筆收到 | 22 筆送出 |

   筆數可能包含擷取重複，不用來推算丟包率。來源 port 在 NAT 前後一致；VM 回包包含 37／91-byte 小 UDP 資料，仍未出現在 Mac 的文字擷取記錄。

因此，此次 **不是我們把 HY2 誤擋在 SSH 白名單外**，也不是只憑本機 Timeout 猜測伺服器未安裝。VM 有送回封包仍不代表它們通過 Azure 邊界、跨境網路、ISP、家用 NAT 並抵達 Mac。

### 未確認的部分

- GFW、ISP／跨境回程過濾、家用路由器／NAT 或其他網路元件，各自仍是候選原因。
- 沒有在家用路由器 WAN／LAN 兩側擷取，不能精確指出丟棄點。
- 小回包同樣不見，不太像單純「只有大封包超過 MTU」；未做完整 MTU／分片測試。
- 未做手機熱點／另一 ISP、其他受控 UDP port、或不同傳輸設定的對照。不需要為臨時香港出口立即做這些工作。

## Workaround — 明確的日本→香港鏈路

保留原生 HY2 節點供未來測試；另建一個使用既有日本節點作 `dialer-proxy` 的 HY2 節點。兩者放在不影響主流量的 `HY2-Test` 群組。

以下只列出需確認的非秘密欄位，**不是完整可啟動設定**；認證欄位必須從私人匯出保留，不放進此 repo。

```yaml
name: hy2-hk-via-jp
type: hysteria2
server: HK_PUBLIC_IP
port: 443
sni: HK_CERTIFICATE_HOSTNAME
dialer-proxy: EXISTING_JP_NODE
```

- `dialer-proxy` 固定指向已驗證可承載 UDP 的日本**節點**，不要指向可能再選到此 HY2 節點的主策略群組，避免循環。
- 不關閉 TLS 驗證，不因為 Timeout 就放寬 SSH 白名單至全網。
- 日本只是前一跳；網站的連線對端通常看見**最後一跳香港伺服器的出口 IP**。須再確認 IP 地理資料庫是否標為 HK，不能只用 Azure region 當證明。
- 加入測試群組不等於一般流量已改走香港。Rule mode 下既有主 `PROXY` 可能仍是日本；只有實際選路到 HY2 的流量會使用香港出口。
- 多一跳會增加延遲，且日本、香港兩端可能各自計算流量費。網站仍可能使用登入帳號、cookie、GPS／定位權限、WebRTC 等其他訊號；IP 在 HK 不保證每個網站的地區判定。

本次 Verge source companion 匯入後，由使用者在原生 UI 重載 local profile，再用 `configs verify RECEIPT_ID` 核對 source／generated／runtime。不要繞過 owner 直接覆寫 generated YAML。

### 香港出口的地區驗證

2026-11-01 另以「現有 Verge 日本路由 → 獨立、僅 localhost 的 HY2 client」發出實際 HTTPS 請求，未切換主代理：

- IP.SB：出口等於香港 VM public IPv4；`country=Hong Kong`、`country_code=HK`、`region=Kowloon`、`isp=Microsoft Azure`、`timezone=Asia/Hong_Kong`。
- Cloudflare trace：相同出口 IP、`loc=HK`、`colo=HKG`。

這是本次臨時香港出口需求的驗收證據，不代表原生直連已修好，也不保證其他網站的地理資料庫／帳號地區判斷一致。

另一次把兩個 source-export 節點放入獨立 client、全域綁定 `en1` 的測試得到 `curl` exit 35；其建構方式與既有 Verge runtime 不同，未追查根因，未作為成功或「既有日本鏈路失效」的證據。不要為了延伸這個旁支而恢復使用者已暫停的除錯。

## Deferred next steps — 只有再次需要直連才恢復

1. 同一台 Mac 改手機熱點，重測原生 HY2；不要同時改密碼、port、VM 或策略，避免失去對照。
2. 如需定位家用 NAT／ISP，經授權後在路由器 WAN／LAN 與 VM 同步看同一 flow。
3. 必要時設計有明確界限的 UDP／QUIC／MTU 對照；涉及新 listener、firewall rule 或服務設定時先審核變更與回復方式。
4. 更新此文件的證據與狀態；沒有新證據時，不把候選原因升格成已確認根因。

## Capture / permission pitfall

在此非互動 CLI 環境，`! sudo -v` 失敗：

```text
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required
```

不要收集對話中的密碼、改 sudoers 或換另一個 agent 繞過。改由使用者在一般 Terminal 自行啟動目標限定的 tcpdump，僅記錄文字摘要，看到 `listening on ...` 後才觸發測試；結束提醒 Ctrl+C。此做法不代表 agent 取得了其他 sudo 權限。

## Prevention / related

- 區分 VM running、service running、配置驗證、client 認證成功、特定路徑成功與地區判定；不能互相替代。
- 除錯副本只存權限受限的暫存目錄，輸出先遮蔽 credentials，完成後清除。
- 實際 endpoint 從本機 inventory 的 `azure-hk-hy2-tl`／`hy2-hk` 查詢；此筆記刻意不保存雲端帳號、訂閱 ID 或密碼。
- [Server deployment](../docs/server-deployment.md)
- [Diagnostics and routing](../docs/diagnostics-and-routing.md)
- [Proxies and groups](../docs/proxies-and-groups.md)
