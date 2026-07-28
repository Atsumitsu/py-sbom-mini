
# py-sbom-mini

A lightweight Python SBOM generator fully compliant with NTIA minimum elements, CISA 2025, and SPDX 2.3.

`py-sbom-mini` は、Pythonプロジェクトのソースコードを静的解析し、NTIAおよびCISA 2025の最小要件に完全準拠したSPDX 2.3 JSON形式のSBOMを自動生成する軽量ツールです。別途公開しているSBOMビューア『SBOMcraft』での検証・閲覧に最適化されています。

## 特徴 (Features)

- **自動インポート解析:** 指定されたソースディレクトリから標準ライブラリ以外の `import` 文を自動抽出。
- **仮想環境 (.venv) 連動:** 仮想環境内を調査し、正確なパッケージバージョンとSHA-256ハッシュ値を自動算出。
- **CISA 2025 対応:** 従来のツールでは不足しがちなライフサイクルコンテキスト情報（Generation Context）の埋め込みに対応。
- **マルチOS対応:** Windows環境だけでなく、LinuxやMac環境でもそのまま動作可能。
- **簡単管理:** 共通のメタデータは外部設定ファイルで一括管理し、作成の手間を大幅に削減。

## Usage (使い方)

1. 本リポジトリをクローンします:
```
      git clone [https://github.com/あなたのユーザー名/py-sbom-mini.git](https://github.com/あなたのユーザー名/py-sbom-mini.git)
   cd py-sbom-mini
```

2. `sbom_config.txt` を作成または編集し、プロジェクトのプロファイルを記述します（詳細は後述）。
3. 解析対象のPythonプロジェクトのパスを指定して実行します:
```
python main.py --path /path/to/your/python/project --depth all
```



## Options (オプション)

```bash
usage: main.py [-h] [-p PATH] [-v VERSION] [-o OUTPUT] [-d DEPTH] [-c CONFIG] [-b BINARY]

options:
  -h, --help            show this help message and exit
  -p, --path PATH       解析対象のPythonプロジェクトのルート (デフォルト: ".")
  -v, --version VERSION プロジェクトのバージョン (デフォルト: "1.0.0")
  -o, --output OUTPUT   出力ファイル名 (デフォルト: "sbom.spdx.json")
  -d, --depth DEPTH     解析する依存関係の階層（デフォルト: "1", or "all"）
  -c, --config CONFIG   設定ファイル(sbom_config.txt)のパス
  -b, --binary BINARY   RootPackage対象のバイナリファイルパス（ハッシュ計算用）

```

### 使用例:

```bash
# 隣のディレクトリにあるSBOMcraftプロジェクトを解析し、全階層の依存関係を含める
python main.py --path "..\SBOMcraft" --output "sbomcraft_spdx.json" -v 5.2.0.0 --depth all

# カレントディレクトリを解析し、特定の設定ファイルを指定する
python main.py --path "." --output "py-sbom-mini_spdx.json" -v 1.0.0 -c ".\sbom_config_py-sbom-mini.txt"

```

## Configuration (設定ファイルの書き方)

`sbom_config.txt` に以下の形式で値を設定することで、SBOMの共通メタデータを制御できます。

```text
supplier_name: Your Name
supplier_email: security-contact@example.com
is_person: false
product_name: My-Application
document_creator: Security Team
data_confidentiality: TLP:CLEAR
root_license_declared: your license
root_copyright_text: Copyright (c) year your name
root_download_location: [https://github.com/your-org/my-app](https://github.com/your-org/my-app)
generation_context: Source

```

## License

SPDX-License-Identifier: Apache-2.0

## version
2026/7/11 ver 1.0
2026/7/29 ver 1.1 importlib対応
