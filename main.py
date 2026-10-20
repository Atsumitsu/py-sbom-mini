# main.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 XZ Manj


import os
import sys
import ast
import json
import fnmatch
import argparse
import subprocess
import uuid
import hashlib
import re
from datetime import datetime, timezone
import importlib.metadata 

PACKAGE_MAPPING = {
    "yaml": "PyYAML",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "PIL": "Pillow",
    "bs4": "beautifulsoup4",
}

# 代表的な SPDX ライセンス ID のセット（必要に応じて拡張可能）
KNOWN_SPDX_IDS = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only", "LGPL-3.0-only",
    "MPL-2.0", "PSF-2.0", "Zlib", "Unlicense"
}


def normalize_and_register_license_with_source(pkg, pkg_name, custom_licenses_list):
    """
    ライセンスの出所を追跡しながら、SPDXライセンス式をパース・正規化し、
    (SPDX式, 取得元のソース情報) のタプルを返す。
    """
    raw_license = None
    source_origin = "Unknown"

    # --- 1. 第1優先: License-Expression (PEP 639 等) ---
    if pkg.get("License-Expression"):
        raw_license = pkg.get("License-Expression")
        source_origin = "Metadata: License-Expression"

    # --- 2. 第2優先: License フィールド (ただし "UNKNOWN" や空でない場合) ---
    if (not raw_license or raw_license.strip() == "" or raw_license.strip().upper() == "UNKNOWN") and pkg.get("License"):
        raw_license = pkg.get("License")
        source_origin = "Metadata: License Field"

    # --- 3. 第3優先: Classifiers からの逆引き (第1・第2が未設定/UNKNOWNの場合の補完) ---
    classifiers = pkg.get("Classifiers", [])
    if isinstance(classifiers, str):
        classifiers = [c.strip() for c in classifiers.split(",")]

    inferred_from_clf = None
    for clf in classifiers:
        if "License :: OSI Approved ::" in clf:
            clf_lower = clf.lower()
            if "mit license" in clf_lower: inferred_from_clf = "MIT"; break
            elif "apache software license" in clf_lower or "apache-2.0" in clf_lower: inferred_from_clf = "Apache-2.0"; break
            elif "bsd license" in clf_lower:
                inferred_from_clf = "BSD-3-Clause" if "3" in clf_lower else "BSD-2-Clause"; break
            elif "isc license" in clf_lower: inferred_from_clf = "ISC"; break

    # もし第1・第2で有効なものが取れなかった（または UNKNOWN だった）場合、Classifiers の推論結果を採用する
    if (not raw_license or raw_license.strip() == "" or raw_license.strip().upper() == "UNKNOWN") and inferred_from_clf:
        return inferred_from_clf, "PyPI Classifiers (OSI Approved)"

    # それでもダメな場合の最終フォールバック
    if not raw_license or raw_license.strip() == "" or raw_license.strip().upper() == "UNKNOWN":
        return "NOASSERTION", "Fallback (NOASSERTION)"

    location = pkg.get("Location") # 🌟 パッケージのインストール先パスを取得

    cleaned = raw_license.strip()

    # 演算子やカッコでトークン分解して個別に正規化（AND, OR, WITH対応）
    tokens = re.split(r'(\s+and\s+|\s+or\s+|\s+with\s+|\(|\))', cleaned, flags=re.IGNORECASE)
    normalized_tokens = []
    
    for token in tokens:
        stripped_token = token.strip()
        if not stripped_token:
            continue
        if re.match(r'^(and|or|with|\(|\))$', stripped_token, re.IGNORECASE):
            normalized_tokens.append(stripped_token.upper() if stripped_token.lower() in ['and', 'or', 'with'] else stripped_token)
            continue
            
        # 🌟 location を引数に渡す
        norm_sub = _normalize_single_license(stripped_token, inferred_from_clf, pkg_name, location, custom_licenses_list)
        normalized_tokens.append(norm_sub)
        
    reconstructed_expression = " ".join(normalized_tokens)
    return reconstructed_expression, source_origin

def extract_license_text_from_dist_info(location, pkg_name):
    """
    .dist-info 配下の LICENSE, LICENCE ファイル等からライセンス条文の本文を抽出する
    """
    if not location or not os.path.exists(location):
        return None
    
    normalized_name = pkg_name.replace("-", "_").lower()
    dist_info_path = None
    
    for entry in os.listdir(location):
        if entry.lower().startswith(normalized_name) and entry.endswith(".dist-info"):
            dist_info_path = os.path.join(location, entry)
            break
            
    if not dist_info_path:
        print(f"   [License File] ⚠️ {pkg_name}: .dist-info ディレクトリが見つかりませんでした (Location: {location})")
        return None

    # LICENSE または LICENCE で始まるファイルを優先的に探す
    target_files = [f for f in os.listdir(dist_info_path) if f.upper().startswith(("LICENSE", "LICENCE", "COPYING"))]

    for file_name in target_files:
        file_path = os.path.join(dist_info_path, file_name)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                    if content:
                        # 🌟 見つかって正常に読み込めた場合のメッセージとフルパス出力
                        abs_file_path = os.path.abspath(file_path)
                        print(f"   [License File] 📄 検出成功 [{pkg_name}]: ライセンスファイルを読み込みました -> {abs_file_path}")
                        return content
                    else:
                        print(f"   [License File] ⚠️ {pkg_name}: ライセンスファイルは見つかりましたが、中身が空です: {file_path}")
            except Exception as e:
                # 🌟 ファイル読み込みに失敗した場合のメッセージ出力
                print(f"   [License File] ❌ {pkg_name}: ライセンスファイルの読み込みに失敗しました ({file_path}): {e}")

    print(f"   [License File] ℹ️ {pkg_name}: .dist-info 内に対象のライセンスファイルが見つかりませんでした。")
    return None

def _normalize_single_license(single_str, inferred_clf, pkg_name, location, custom_licenses_list):
    """ 単一のライセンス文字列（式の中のパーツ）を正規化するヘルパー """
    lower_s = single_str.lower()
    
    if "apache" in lower_s and "2" in lower_s:
        return "Apache-2.0"
    if lower_s == "mit" or "mit license" in lower_s:
        return "MIT"
    if "bsd" in lower_s:
        return "BSD-3-Clause" if "3" in lower_s else "BSD-2-Clause"
    if "isc" in lower_s:
        return "ISC"
    #  ライセンス変換：救済
#    if "psfl" in lower_s:
#        return "PSF-2.0"
        
    if single_str in KNOWN_SPDX_IDS:
        return single_str
        
    # もし部分一致で認識できず、全体として無名かつ Classifier から推論できるならそれを使う
    if inferred_clf and (single_str == "NOASSERTION" or not single_str):
        return inferred_clf

    # どうしても未知の場合は、個別に LicenseRef を生成して登録
    safe_name = re.sub(r'[^a-zA-Z0-9-]', '-', f"-{single_str}").lower()
    license_ref = f"LicenseRef-{safe_name[:40]}" # 長くなりすぎないように制限
    
# 🌟 1. まず .dist-info 内の LICENSE ファイルから実際の本文取得を試みる
    extracted_text = extract_license_text_from_dist_info(location, pkg_name)
    
    # 2. ファイルが見つからない、または空の場合は、従来のメタデータ文字列をフォールバックとして使う
    if not extracted_text:
        extracted_text = single_str

    if not any(item.get("licenseId") == license_ref for item in custom_licenses_list):
        custom_licenses_list.append({
            "licenseId": license_ref,
            "extractedText": extracted_text, # 実ファイルの本文（またはメタデータの文字列）
            "name": f"{single_str}"
        })

    return license_ref

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PythonプロジェクトからNTIA/CISA要件準拠のSPDX 2.3形式SBOMを自動生成するツール"
    )
    parser.add_argument("-p", "--path", default=".", help="解析対象のPythonプロジェクトのルート")
    parser.add_argument("-v", "--version", default="1.0.0", help="プロジェクトのバージョン")
    parser.add_argument("-o", "--output", default="sbom.spdx.json", help="出力ファイル名")
    parser.add_argument("-d", "--depth", default="1", help="階層（'1' または 'all'）")
    parser.add_argument("-c", "--config", default="sbom_config.txt", help="設定ファイルのパス")
    parser.add_argument("-b", "--binary", default=None, help="RootPackage対象のバイナリファイルパス")
    parser.add_argument("--verbose", action="store_true", help="詳細なライセンス解析プロセスとソースを出力する") # 🌟 追加
    return parser.parse_args()

def setup_target_environment(target_path):
    """
    対象プロジェクトの .venv / venv 内の site-packages を sys.path に動的追加する
    """
    possible_site_paths = [
        os.path.join(target_path, ".venv", "Lib", "site-packages"),      # Windows
        os.path.join(target_path, "venv", "Lib", "site-packages"),       # Windows
        os.path.join(target_path, ".venv", "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages"), # Linux/Mac
        os.path.join(target_path, "venv", "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages"),  # Linux/Mac
    ]
    for sp in possible_site_paths:
        if os.path.exists(sp):
            if sp not in sys.path:
                sys.path.insert(0, sp)
            print(f"   [仮想環境検出] site-packages を認識しました: {sp}")
            return sp
    return None

def load_tag_value_config(config_path):
    """ tag:value 形式の外部ファイルを読み込んで辞書にする """
    config = {
        "supplier_name": "UNKNOWN-SUPPLIER",
        "supplier_email": "contact@example.com",
        "is_person": "false",
        "product_name": "Python-Project",
        "document_creator": "Security-Team",
        "data_confidentiality": "TLP:CLEAR",
        "root_license_declared": "NOASSERTION",
        "root_copyright_text": "NOASSERTION",
        "root_download_location": "NOASSERTION",
        "root_binary_path": "",
        "root_purl": "",
        "generation_context": "Source"
    }
    
    if not os.path.exists(config_path):
        print(f"⚠️ 警告: 設定ファイル {config_path} が見つかりません。")
        return config

    with open(config_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if ":" in line:
                idx = line.find(":")
                key = line[:idx].strip()
                val = line[idx+1:].strip()
                config[key] = val
    return config

def calculate_sha256(file_path):
    """ 指定されたバイナリファイルのSHA-256ハッシュ値を計算する """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            print(f"   [ファイル検出] {file_path} ")
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        print(f"   [ファイル未検出] スキップ： {file_path} ")
        return None

def get_package_hash_from_record(location, name):
    """ 🌟 ローカルの .dist-info/RECORD からパッケージのSHA-256ハッシュを抽出する """
    # pipのインストール先から .dist-info フォルダを探す
    # フォルダ名は通常「パッケージ名-バージョン.dist-info」だが、表記揺れを考慮して探す
    if not location or not os.path.exists(location):
        return None
        
    normalized_name = name.replace("-", "_").lower()
    # 1. まず .dist-info/RECORD を探す
    for entry in os.listdir(location):
        if entry.lower().startswith(normalized_name) and entry.endswith(".dist-info"):
            record_path = os.path.join(location, entry, "RECORD")
            if os.path.exists(record_path):
                # RECORDファイル自体のハッシュ値をパッケージの代表ハッシュとする（確実かつ高速）
                return calculate_sha256(record_path)

    # 2. RECORDが見つからない場合（ソースパッケージ等）、内部の .py ファイル等のハッシュをフォールバックとして計算
    try:
        for root, dirs, files in os.walk(location):
            for file in files:
                if file.endswith((".py", ".so", ".pyd", ".dll", ".txt")):
                    file_path = os.path.join(root, file)
                    h = calculate_sha256(file_path)
                    if h: return h
    except Exception:
        pass

    return None

def extract_copyright_from_dist_info(location, pkg_name):
    """
    .dist-info 配下の LICENSE, NOTICE, METADATA 等から Copyright 表記を抽出する
    """
    if not location or not os.path.exists(location):
        return "NOASSERTION"
    
    normalized_name = pkg_name.replace("-", "_").lower()
    dist_info_path = None
    
    for entry in os.listdir(location):
        if entry.lower().startswith(normalized_name) and entry.endswith(".dist-info"):
            dist_info_path = os.path.join(location, entry)
            break
            
    if not dist_info_path:
        return "NOASSERTION"

    copyright_lines = []
    # 検索対象ファイル
    target_files = [f for f in os.listdir(dist_info_path) if f.upper().startswith(("LICENSE", "NOTICE", "COPYRIGHT")) or f == "METADATA"]

    # 正規表現パターン (Copyright, (C), © 表記を検出)
    copyright_pattern = re.compile(r'(copyright\s+(\(c\)\s*|©\s*)?[\d\-\s,]+[^\n]+)', re.IGNORECASE)

    for file_name in target_files:
        file_path = os.path.join(dist_info_path, file_name)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        match = copyright_pattern.search(line)
                        if match:
                            clean_text = match.group(1).strip()
                            if clean_text not in copyright_lines:
                                copyright_lines.append(clean_text)
            except Exception:
                pass

    if copyright_lines:
        return "\n".join(copyright_lines)
    
    return "NOASSERTION"

def load_gitignore_patterns(base_path):
    patterns = ['.git/', '.venv/', 'venv/', '__pycache__/', '*.pyc']
    gitignore_path = os.path.join(base_path, ".gitignore")
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'): patterns.append(line)
    return patterns

def is_ignored(path, patterns, base_path):
    rel_path = os.path.relpath(path, base_path)
    norm_path = rel_path.replace(os.sep, '/')
    parts = norm_path.split('/')
    for pattern in patterns:
        clean_pattern = pattern.rstrip('/')
        if clean_pattern in parts or fnmatch.fnmatch(norm_path, pattern) or fnmatch.fnmatch(os.path.basename(path), clean_pattern): return True
        if pattern.endswith('/') and norm_path.startswith(pattern): return True
    return False

def find_all_py_files(base_path, patterns):
    py_files = []
    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d), patterns, base_path)]
        for file in files:
            if file.endswith(".py") and file != "main.py":
                full_path = os.path.join(root, file)
                print(f"file:{full_path}")
                if not is_ignored(full_path, patterns, base_path): py_files.append(full_path)
    return py_files

def get_imports_from_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        try: root = ast.parse(f.read(), filename=filepath)
        except SyntaxError: return set()
    modules = set()
    for node in ast.walk(root):
        if isinstance(node, ast.Import):
            for n in node.names:
                modules.add(n.name.split('.')[0])
                print(f"import:{n.name.split('.')[0]}")
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module.split('.')[0])
                print(f"import2:{node.module.split('.')[0]}")
    return modules

def get_pip_show_info(package_name, base_path):
    pip_package_name = PACKAGE_MAPPING.get(package_name, package_name)
    
    if pip_package_name == package_name:
        try:
            mapping = importlib.metadata.packages_distributions()
            if package_name in mapping:
                pip_package_name = mapping[package_name][0]
        except Exception:
            pass

    # 🌟 3. 対象プロジェクトの .venv 内の python executable を探索
    venv_python = sys.executable
    possible_venv_paths = [
        os.path.join(base_path, ".venv", "Scripts", "python.exe"),
        os.path.join(base_path, ".venv", "bin", "python"),
        os.path.join(base_path, "venv", "Scripts", "python.exe"),
        os.path.join(base_path, "venv", "bin", "python"),
    ]
    for vp in possible_venv_paths:
        if os.path.exists(vp):
            venv_python = vp
            break

    # 🌟 4. 特定した python.exe を使って pip show を実行
    try:
        result = subprocess.run([venv_python, "-m", "pip", "show", pip_package_name], capture_output=True, text=True, encoding="utf-8", errors="ignore")
        if result.returncode != 0: return None
        info = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                info[key.strip()] = val.strip()
        return info
    except Exception: return None

def trace_dependencies_all(direct_modules, base_path):
    collected_packages = {}
    queue = list(direct_modules)
    processed_modules = set()
    print("4. 外部パッケージの依存関係を再帰的に追跡中（全階層）...")
    while queue:
        current_mod = queue.pop(0)
        if current_mod in processed_modules: continue
        processed_modules.add(current_mod)
        info = get_pip_show_info(current_mod, base_path)
        if info:
            pkg_name = info["Name"]
            if pkg_name not in collected_packages:
                collected_packages[pkg_name] = info
                print(f"   [検出] {pkg_name} (v{info['Version']})")
                requires = info.get("Requires", "")
                if requires:
                    for dep in [d.strip() for d in requires.split(",") if d.strip()]:
                        if dep not in processed_modules: queue.append(dep)
    return collected_packages


def generate_spdx_json(version, packages, direct_package_names, depth_mode, cfg, target_path=".", verbose=False):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_uuid = str(uuid.uuid4())
    
    # 🌟 設定ファイルのフラグから、プレフィックスを動的に決定
    document_creator_is_person_flag = cfg.get("document_creator_is_person", "false").lower() == "true"
    is_person_flag = cfg.get("is_person", "false").lower() == "true"
    my_supplier_prefix = "Person" if is_person_flag else "Organization"
    # 🌟 CISAが要求する「Generation Context」のコメント文字列を構築
    gen_ctx = cfg.get("generation_context", "Source")
    comment_str = f"Data Confidentiality: {cfg['data_confidentiality']} | Type: {gen_ctx} | Generation Context: {gen_ctx}"
    
    # 🌟 カスタムライセンス（LicenseRef）を格納するリスト
    other_licenses_list = []

    spdx_doc = {
        "documentNamespace": f"http://spdx.org/spdxdocs/{cfg['product_name']}-{version}-{doc_uuid}",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": cfg['product_name'],
        "comment": comment_str,
        "creationInfo": {
            "created": now,
            "creators": [
            # ドキュメントの作成組織/作成者は規約通りそのまま配置
                f"Organization: {cfg['document_creator']}" if not document_creator_is_person_flag else f"Person: {cfg['document_creator']}",
                "Tool: py-sbom-mini-1.1.0"
            ]
        },
        "packages": [],
        "relationships": []
    }
    
    # ルートパッケージの構成
    root_package = {
        "name": cfg['product_name'],
        "SPDXID": "SPDXRef-RootPackage",
        "versionInfo": version,
        "supplier": f"{my_supplier_prefix}: {cfg['supplier_name']}",
        "downloadLocation": cfg['root_download_location'],
        "filesAnalyzed": False,
        "licenseConcluded": cfg['root_license_declared'],
        "licenseDeclared": cfg['root_license_declared'],
        "copyrightText": cfg['root_copyright_text'],
        "summary": "Root application container for the project",
        "comment": f"Generation Context: {gen_ctx}"
    }
    
    # バイナリパスが設定されており、ファイルが存在すればSHA-256を計算して追加
    print(f"   [Debug] 現在の作業ディレクトリ(CWD): {os.getcwd()}")
    print(f"   [Debug] 設定されたパス: {cfg.get('root_binary_path')}")
    print(f"   [Debug] 絶対パスに変換すると: {os.path.abspath(cfg.get('root_binary_path', ''))}")

# 🌟 ルートパッケージのハッシュ計算（バイナリ未指定時はソースファイルを自動探索してハッシュ化）
    target_hash_path = cfg.get("root_binary_path")
    if not target_hash_path or not os.path.exists(target_hash_path):
        # 指定がない場合、プロジェクト内の代表的なソースファイル（main.py や最初の .py）を探す
        potential_main = os.path.join(target_path if 'target_path' in locals() else ".", "main.py")
        if os.path.exists(potential_main):
            target_hash_path = potential_main
        else:
            # 探索で見つかった最初の .py ファイルを利用
            for root, dirs, files in os.walk(target_path if 'target_path' in locals() else "."):
                py_candidates = [os.path.join(root, f) for f in files if f.endswith(".py") and f != "main.py"]
                if py_candidates:
                    target_hash_path = py_candidates[0]
                    break

    if target_hash_path and os.path.exists(target_hash_path):
        file_hash = calculate_sha256(target_hash_path)
        if file_hash:
            root_package["checksums"] = [
                {
                    "algorithm": "SHA256",
                    "checksumValue": file_hash
                }
            ]
            print(f"   [Root Hash計算完了] 対象: {target_hash_path} -> {file_hash[:8]}...")
        else:
            print(f"   ⚠️ 警告: ファイルのハッシュ計算に失敗しました: {target_hash_path}")
    else:
        print(f"   ⚠️ 警告: ハッシュ対象となるファイル（バイナリまたはソースファイル）が見つかりません。")    

    # ルートパッケージ用のPURLを追加（設定にあれば）
    if cfg.get("root_purl"):
        root_package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": cfg["root_purl"]
            }
        ]
        
    spdx_doc["packages"].append(root_package)
    
    # 関係性の定義（DOCUMENT -> Root）
    spdx_doc["relationships"].append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-RootPackage"
    })
    
    # Root -> 各直接パッケージへの依存
    for direct_pkg in sorted(direct_package_names):
        if direct_pkg in packages:
            safe_direct_id = f"SPDXRef-Package-{direct_pkg.replace('_', '-')}"
            spdx_doc["relationships"].append({
                "spdxElementId": "SPDXRef-RootPackage",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": safe_direct_id
            })
    
    # 外部パッケージの追加
    for pkg_name, pkg in packages.items():
        raw_license = pkg.get("License-Expression") or pkg.get("License", "NOASSERTION")
        
        # 🌟 pip show の結果に含まれる classifiers（複数行またはリスト）を取得する想定
        # ※ pip show の出力仕様によっては、METADATAからの直接パース等で classifiers リストを取得できるように拡張するとより精度が上がります
        classifiers = pkg.get("Classifiers", [])
        if isinstance(classifiers, str):
            classifiers = [c.strip() for c in classifiers.split(",")]

        # ライセンスの正規化と LicenseRef の自動生成判定
        license_declared,license_source = normalize_and_register_license_with_source(pkg, pkg["Name"], other_licenses_list)
#        normalize_and_register_license(raw_license, classifiers, pkg["Name"], other_licenses_list)

        # 🌟 詳細出力モードが有効な場合のログ表示
        if verbose:
            print(f"      [License Detail] Package: {pkg['Name']} (v{pkg.get('Version')})")
            print(f"        -> 取得元ソース: {license_source}")
            print(f"        -> 生データ表現: {pkg.get('License') or pkg.get('License-Expression', 'N/A')}")
            print(f"        -> 確定 SPDX ID / Ref: {license_declared}")

        raw_author = pkg.get('Author', '').strip()
        external_supplier_prefix = "Organization"
        
        if not raw_author or raw_author == "":
            raw_email = pkg.get('Author-email', '').strip()
            if raw_email and " <" in raw_email:
                raw_author = raw_email.split(" <")[0]
            else:
                # 最終フォールバックで自分の設定を使う場合も、個人/組織設定を反映
                raw_author = cfg['supplier_name']
                external_supplier_prefix = my_supplier_prefix

        # 🌟 Copyright 情報の探索・決定ロジック
        copyright_text = extract_copyright_from_dist_info(pkg.get("Location"), pkg["Name"])
        
        # .dist-info から取得できず、Author 情報が存在する場合は「Copyright (c) <Author>」形式でフォールバック
        if copyright_text == "NOASSERTION" and raw_author and raw_author != cfg['supplier_name']:
            copyright_text = f"Copyright (c) {raw_author}"

        safe_pkg_id = f"SPDXRef-Package-{pkg['Name'].replace('_', '-')}"

        pkg_node = {
            "name": pkg["Name"],
            "SPDXID": safe_pkg_id,
            "versionInfo": pkg["Version"],
            # 外部パッケージの supplier への反映
            "supplier": f"{external_supplier_prefix}: {raw_author}", 
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": license_declared,
            "licenseDeclared": license_declared,
            "copyrightText": copyright_text,
            "summary": pkg.get("Summary", ""),
            "homepage": pkg.get("Home-page", "NOASSERTION"),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{pkg['Name'].lower()}@{pkg['Version']}"
                }
            ]
        }
        
        # 調査パッケージのローカルHash値（SHA-256）を自動取得して組み込み
        pkg_hash = get_package_hash_from_record(pkg.get("Location"), pkg["Name"])
        if pkg_hash:
            pkg_node["checksums"] = [
                {
                    "algorithm": "SHA256",
                    "checksumValue": pkg_hash
                }
            ]

        spdx_doc["packages"].append(pkg_node)
        
        if depth_mode == "all":
            requires = pkg.get("Requires", "")
            if requires:
                dep_packages = [d.strip() for d in requires.split(",") if d.strip()]
                for dep in dep_packages:
                    matched_pkg_name = next((k for k in packages.keys() if k.lower() == dep.lower()), None)
                    if matched_pkg_name:
                        safe_parent_id = f"SPDXRef-Package-{pkg['Name'].replace('_', '-')}"
                        safe_child_id = f"SPDXRef-Package-{matched_pkg_name.replace('_', '-')}"
                        spdx_doc["relationships"].append({
                            "spdxElementId": safe_parent_id,
                            "relationshipType": "DEPENDS_ON",
                            "relatedSpdxElement": safe_child_id
                        })
    # 🌟 カスタムライセンス（LicenseRef）が生成されている場合、SPDXドキュメントに `otherLicenses` を追加
    if other_licenses_list:
        spdx_doc["hasExtractedLicensingInfos"] = other_licenses_list

    return spdx_doc

# main関数はそのまま維持（変更ありません）
def main():
    args = parse_arguments()
    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"❌ エラー: パスが見つかりません: {target_path}")
        sys.exit(1)

    # 🌟 1つ目のやり方でも動作するように、対象の .venv の site-packages を先頭にセットする
    setup_target_environment(target_path)

    cfg = load_tag_value_config(args.config)

    # コマンドライン引数でバイナリが指定されていれば、それを最優先する
    if args.binary:
        cfg["root_binary_path"] = args.binary
    
    print(f"📂 解析対象ディレクトリ: {target_path}")
    print(f"製品名: {cfg['product_name']} (v{args.version})")
    print(f"階層モード: {args.depth}")
    if cfg.get("root_binary_path"):
        print(f"対象バイナリ: {cfg['root_binary_path']}")

    print("1. .gitignore のパターンを読み込み中...")
    gitignore_patterns = load_gitignore_patterns(target_path)
    
    print("2. スキャン対象の .py ファイルを検索中...")
    py_files = find_all_py_files(target_path, gitignore_patterns)
    print(f"   👉 調査対象ファイル: {len(py_files)} 件")
    
    print("\n3. 各ファイルのインポート文を解析中...")
    all_imported_modules = set()
    for filepath in py_files:
        modules = get_imports_from_file(filepath)
        all_imported_modules.update(modules)
        
    valid_packages = {}
    direct_package_names = set()
    
    if args.depth == "all":
        valid_packages = trace_dependencies_all(all_imported_modules, target_path)
        for mod in all_imported_modules:
            info = get_pip_show_info(mod, target_path)
            if info: direct_package_names.add(info["Name"])
    else:
        print("\n4. 外部パッケージ情報を pip show から取得中（階層1のみ）...")
        for mod in sorted(all_imported_modules):
            info = get_pip_show_info(mod, target_path)
            if info:
                valid_packages[info["Name"]] = info
                direct_package_names.add(info["Name"])
                print(f"   [検出] {info['Name']} (v{info['Version']})")
            
    print(f"\n5. SPDX形式のSBOMを生成中...")
    sbom_data = generate_spdx_json(args.version, valid_packages, direct_package_names, args.depth, cfg,target_path,verbose=args.verbose)
    
    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=2, ensure_ascii=False)
        
    print(f"\n🎉 完了しました！ -> {output_path} (総パッケージ数: {len(valid_packages) + 1}個 *Root含む)")

if __name__ == "__main__":
    main()