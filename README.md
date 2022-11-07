# Vuls: VULnerability Scanner

TODO
- [ ] scan cmd: 各種パッケージマネージャのscannerを持たせて，最後にforで回しながら，パッケージ情報を収集するイメージ（Debian→dpkg, RedHat→rpm，もしnpmがあれば，dpkg, npmみたいに……
- [ ] detect cmd: scan結果から，脆弱性を検知したり，CPEやFreeBSD，RaspberryPiでのコマンドによる脆弱性検知を行うだけ，結果はJSONで持つ
- [ ] report cmd: formatを変えたり，JSON→XML，CSV，SBOMや，S3やGCS，Slackなどにuploadする部分，あとはCVSSやSeverityでfilterなどをする
- [ ] server cmd: scan, detect, reportをrequest bodyにJSON形式で受け取り，実行する．また，db searchも行えるように．
- [ ] config init cmd: templateになるようなconfig.tomlを生成する
- [ ] db fetch cmd: GHCRから持ってくる
- [ ] db create cmd: 統一するデータソースをcloneしてきて，DBを生成する(DB: boltDB, SQLite3, MySQL, PostgreSQL, Redis)
- [ ] db search cmd: DBからCVE，パッケージを検索する
- [ ] db edit cmd: DBにあるアドバイザリを変更，追加，削除できるように
- [ ] tui cmd: unicordを使えるように，よりrichなviewを作る
- [ ] binaryにSBOMを埋め込む