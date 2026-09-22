# 配置拓樸與群組關係

`topology` 讀取完整 Clash／Mihomo YAML，列出 rules、群組、provider 與 proxy
之間的關係。預設為靜態配置圖；`--live` 另外讀取目前群組選擇與 provider 成員。
這些箭頭表示配置引用／選擇／dialer 依賴，不代表已觀察到的流量或實體網路跳點。

```sh
lazyclash topology --file config.yaml
cat config.yaml | lazyclash topology --file - --format mermaid > topology.mmd
lazyclash --target server topology
lazyclash --target server topology --live
lazyclash --target server topology --source-path /srv/mihomo/config.yaml
lazyclash topology --file config.yaml --view relations --focus PROXY
lazyclash topology --file config.yaml --json
```

`--file` 是本機檔案／stdin，完全離線，不需要有效的 lazyclash 設定或核心 binary。
它不能與 `--target`、`--source-path` 或 `--live` 混用。
`--source-path` 是選定 target 主機上的路徑，包括 SSH host 的 Docker bind source；
它只是一次性的讀取，不建立可寫來源綁定。

未指定路徑時，target 使用既有 node/group source：native／managed YAML、Docker
的 host path，或 Verge 的 `clash-verge.yaml` 生成快照。這個快照不證明核心已載入它。
`source_config` 仍只作憑證發現，不自動當作完整配置來源。
沒有完整 YAML 的 API-only target 可用 `--live`，結果會標明缺少宣告資訊。
若明確指定的 YAML 讀取失敗，會回報錯誤。

## 圖與資料

- `PROXY → Auto → proxy` 是群組成員／選擇關係。`dialer` 虛線表示節點連線使用另一個
  outbound；provider 的 `dialer-override` 是套用到供應節點的宣告。
- `FINAL` 按 YAML 中的實際定義解析；`MATCH,FINAL` 顯示為兜底規則指向 FINAL 群組。
- 一般規則依目的 policy 彙總。JSON 的 `rules` 保留原始順序；TUI 節點詳情可查看
  指向該 policy 的規則。未知規則語法、缺失引用與循環保留診斷。
- 靜態讀取不下載 provider，也不執行核心／Script。Inline payload 可直接呈現；
  `include-all` 與 filter 留作宣告，實際動態成員透過 `--live` 取得。
- Runtime edges 保留自己的來源與時間。它們不覆蓋配置 edges，也不證明同名節點具有
  相同憑證。讀取不觸發 provider update、health check、URLTest 或 reload。

終端圖由固定版本的 [mermaid-ascii](https://github.com/AlexanderGrooff/mermaid-ascii)
Go library 內建渲染，不必另裝執行檔。Mermaid 使用同一份圖模型；標籤中容易被當成
語法的標點會換成相似的 Unicode 字元，完整名稱保留在 JSON／relations。
UUID、密碼及 provider URL 不進入圖模型。

超過 120 個節點、240 條關係、過長標籤或含循環時，終端圖會顯示原因並改呈現
關係列表；`--focus NAME` 可以縮小到該節點的上下游。Mermaid／JSON 保留完整圖。
SVG 匯出暫列 backlog，第一版沒有 Node／Chromium 依賴。

## 互動瀏覽

```sh
lazyclash --target server topology --interactive
lazyclash topology --file config.yaml --interactive
```

Dashboard 的 `:` 選單提供 **Routing topology: configuration / current selections**。
它透過同一個互動瀏覽器執行，read-only 模式也可使用。

| 操作 | 按鍵 |
|---|---|
| 選節點／捲動內容 | ↑↓、j/k、Page Up/Down |
| 切換節點與內容區 | Tab／Shift+Tab |
| 搜尋；結束搜尋 | `/`；Enter |
| 聚焦所選節點／恢復全圖 | Enter／`a` |
| 圖與關係列表切換 | `v` |
| Mermaid source／終端圖 | `m` |
| 複製目前子圖的 Mermaid | `y` |
| 靜態／即時切換；重新讀取 | `s`；`r` |
| 水平移動內容／重設捲動 | ←→、h/l；Home |
| SSH 認證（讀取要求時） | `A` |
| 說明／返回 | `?`／Esc、q |

讀取期間可繼續瀏覽前一份快照；錯誤保留資料，過期讀取／排版結果會被丟棄。
窄畫面只顯示目前聚焦的區域，Tab 仍可切換。
