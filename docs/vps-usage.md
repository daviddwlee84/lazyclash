# VPS 流量與雲端帳務用量

Oracle、Azure 的 VPS 可透過官方 CLI 查詢月流量。`servers usage` 由代理服務找到
對應主機；同一個 server 匯入多個 client target，仍共用同一台 VM 的雲端資料。
查詢不安裝 agent、不重啟服務、不改變雲端資源，也不儲存本地流量計數器。

```sh
lazyclash vps usage "${LC_HOST:?registered VPS ID}" --json
lazyclash servers usage "${LC_SERVER:?proxy server ID}" --json
lazyclash --read-only vps usage "${LC_HOST:?registered VPS ID}" \
  --month "${LC_MONTH:?UTC month YYYY-MM}" --json
```

不加 `--json` 顯示可讀摘要。TUI 的 `:` → **Servers / VPS** 中選擇主機或代理服務，
按 `u` 查詢／更新本月用量；一般 Overview 更新不會輪詢雲端 API。歷史月份使用 CLI。

查看 client 節點與 server／VPS 的對應：

```sh
lazyclash --target "${LC_TARGET:?registered client target}" servers connections --json
```

這會比對保存的 import receipt、目前 source binding 與節點的 semantic hash。
`source-matches` 表示持久化 source 仍符合匯入定義；不代表當下所有連線都使用該節點。
節點被修改、移除或 source 暫時無法讀取會分別標示，不輸出節點密碼或金鑰。
Servers / VPS 詳細資訊也會顯示保存的 target／節點關聯；一般 TUI inventory 更新只讀
本機記錄，會清楚標示這些是先前匯入的證據，沒有重新驗證遠端 source／runtime。

## 連結既有主機

由 lazyclash 建立且保有完整操作記錄的 Oracle／Azure VM，可沿用既有雲端身分。
以 `vps register` 加入的主機，需要一次 `vps bind-cloud`，將該主機連結到實際
instance／VM。這只保存觀測用的身分與資源資訊；`owned=false` 不會因此變成
`true`，也不會取得刪除或控制原有 VM 的權限。

先登入已安裝的官方 CLI；需要安裝／登入指引時可用 `lazyclash vps guide --provider
oracle` 或 `--provider azure`。以下變數須根據實際帳戶設定，缺值會直接停止命令。

Oracle 預覽：

```sh
lazyclash vps bind-cloud "${LC_HOST:?registered VPS ID}" --provider oracle \
  --profile "${LC_OCI_PROFILE:-DEFAULT}" --region "${LC_REGION:?OCI region}" \
  --resource-id "${LC_INSTANCE_OCID:?instance OCID}" \
  --tenancy "${LC_TENANCY_OCID:?tenancy OCID}" --json
```

檢查 instance、tenancy、region、主機位址與 warnings 後，把預覽中的 digest 設成
`LC_BIND_DIGEST`，用同一組參數保存。不要自動擷取 digest 後立即套用。

```sh
lazyclash vps bind-cloud "${LC_HOST:?registered VPS ID}" --provider oracle \
  --profile "${LC_OCI_PROFILE:-DEFAULT}" --region "${LC_REGION:?OCI region}" \
  --resource-id "${LC_INSTANCE_OCID:?instance OCID}" \
  --tenancy "${LC_TENANCY_OCID:?tenancy OCID}" \
  --yes --expect "${LC_BIND_DIGEST:?digest from the reviewed preview}" --json
```

Azure 使用明確的 subscription 與完整 VM resource ID：

```sh
lazyclash vps bind-cloud "${LC_HOST:?registered VPS ID}" --provider azure \
  --subscription "${LC_SUBSCRIPTION:?Azure subscription UUID}" \
  --region "${LC_REGION:?Azure region}" \
  --resource-id "${LC_VM_ID:?full Azure VM resource ID}" --json
```

Azure 也先檢查預覽，再以相同參數加上
`--yes --expect "${LC_BIND_DIGEST:?digest from the reviewed preview}"` 保存。
`bind-cloud` 的套用只寫本地 inventory，因此在 `--read-only` 下禁止；預覽與
`usage` 可以唯讀執行。帳戶或 VM 身分不符時會停止查詢，須重新檢查 binding。

## 如何解讀數字

| 區塊 | 意義 | 不代表什麼 |
|---|---|---|
| VM observed | 雲端 Monitoring 的整台 VM inbound／outbound bytes，含各網卡的流量 | 單一 profile 的流量、可直接計費的 Internet egress |
| Hourly coverage | 有數值的小時樣本／所選時間範圍小時數、最新樣本時間、`PARTIAL` | 缺少樣本等於沒有流量 |
| Provider billing | 雲端回報的 network／Bandwidth meter、原生單位、回報日期；可用時保留實際回報費用 | 即時帳單、剩餘試用金或免費流量餘額 |
| Published allowance | 公開價格中的共享免費額度背景 | 每台 VM 各自擁有同樣的免費額度 |

Oracle 使用 `oci_vcn` 的 `VnicFromNetworkBytes`／`VnicToNetworkBytes`，篩選
instance ID 並加總回傳的 VNIC streams。Azure 使用整台 VM 的 `Network In Total`／
`Network Out Total`，以小時 `Total` 加總；不需要 guest agent。
[Oracle VNIC 指標](https://docs.oracle.com/en-us/iaas/Content/Network/Reference/vnicmetrics.htm)、
[Azure VM 指標](https://learn.microsoft.com/en-us/azure/virtual-machines/monitor-vm-reference)。

帳務資料與 Monitoring 分開呈現。Oracle 查詢所選 tenancy 的 Virtual Cloud Network
meters，依 SKU 與原生單位分組；Azure 查詢所選 subscription 的 Bandwidth meters，
依 meter ID、單位與幣別分組，因此包含其他資源的帳務資料。Internet 與跨洲流量
保留各自 meter。`GB Months`、`10 GB`、`1 TB` 等帳務單位原樣呈現；不從字串中的
數字推導 bytes，也不以 VM observed bytes 扣減共享 allowance。

Oracle 公開 Internet egress 優惠為每月前 10 TB，依來源價格區／SKU 分組；Azure
公開 Internet 價格有每月前 100 GB 免費級距。此功能尚未核實帳戶間的完整 pooling
規則，因此不計算「剩餘 quota」、百分比或超額費用。
[Oracle 價格](https://www.oracle.com/cloud/networking/virtual-cloud-network/pricing/)、
[Oracle 來源價格區／SKU 說明](https://www.oracle.com/news/announcement/oracle-joins-cloudflare-bandwidth-alliance-2021-11-10/)、
[Azure 頻寬價格](https://azure.microsoft.com/en-us/pricing/details/bandwidth/)。

Azure 帳務首版支援 legacy Consumption Usage Details（例如 Visual Studio／MOSP
訂閱）；EA／MCA 所需的 Cost Details 尚未支援，會明確標為 unavailable。帳務權限
不足或資料格式不支援時，仍保留可讀的 VM 流量。停用中的訂閱只要歷史資料仍可讀，
就能查詢；不會重新啟用訂閱。Azure pay-as-you-go 帳務可能延遲最多 72 小時，費用
也可能在出帳前調整。
[Microsoft 帳務介面說明](https://learn.microsoft.com/en-us/azure/cost-management-billing/automate/get-usage-details-legacy-customer)、
[帳務更新時效](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/understand-cost-mgt-data)。

## 月份與資料完整性

`--month YYYY-MM` 使用 UTC 日曆月。預設是本月月初至現在；過去月份是月初至
次月月初，不包含次月資料。未來月份、格式錯誤或超過 Monitoring 保存期限的完整
月份會在雲端查詢前被拒絕：Oracle 一小時解析度最多回查 90 天，Azure platform
metrics 通常保存 93 天。即使帳務資料能保存更久，本指令仍要求整個月份的觀測
窗口在支援期限內；目前沒有本地歷史封存或超期限帳務專用模式。
[Oracle 查詢期限](https://docs.oracle.com/en-us/iaas/Content/Monitoring/Tasks/query-metric-resolution.htm)、
[Azure metrics 保存期限](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-platform-metrics)。

沒有資料顯示為 unknown／no-data，不會補零。VM 在月中建立、停止回報、權限不足、
未回傳完整樣本或資料延遲，都可能出現 `PARTIAL`；已有樣本的真實零值仍會顯示零。
最新時間是 provider 的樣本／帳務日期，不是「目前已結算至此」的保證。Overview
既有的 Mihomo 上下傳數字是 controller 範圍的計數，與這裡的雲端用量不同。
