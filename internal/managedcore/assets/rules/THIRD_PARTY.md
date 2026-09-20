# 第三方資料與來源

自有程式與手工規則沿用根目錄的 MIT 授權。`vendor/metacubex/` 是
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的原始資料鏡像，
其上游授權文字保存在該目錄的 `LICENSE`，來源與每個檔案的 revision、URL、
SHA-256 保存在 `upstreams.lock.json`。鏡像資料不重新標示為本專案的 MIT。

上游資料整合 v2fly/domain-list-community、Loyalsoldier 與其他資料來源；
保存的 `vendor/metacubex/README.md` 列出其來源及致謝。散布建置產物時，
必須保留這份說明、上游 LICENSE／README 與 lock；builder 已將它們納入 manifest。

資料分類不代表本專案採納上游的路由政策。上游例子中的 DIRECT／PROXY、
地區偏好、DNS 及自動切換行為都需要另行評估。
