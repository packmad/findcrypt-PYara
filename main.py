import argparse
import json
import os
import sys
import yara
from os.path import abspath, join, isfile, realpath, dirname, isdir
from typing import Dict, List, Optional
from tqdm import tqdm
from multiprocessing import Pool


CRYPTO_SIGN_YAR = 'crypto_signatures.yar'
YARA_RULES_PATH = join(abspath(dirname(__file__)), 'data', CRYPTO_SIGN_YAR)
YARA_COMPILED_PATH = join(abspath(dirname(__file__)), 'data', 'crypto_signatures.yarc')
RULES = None


def yara_files_check_n_load():
    if not isfile(YARA_RULES_PATH):
        import requests
        url = 'https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar'
        print(f"> File '{CRYPTO_SIGN_YAR}' not found! Downloading...")
        r = requests.get(url, allow_redirects=True)
        with open(YARA_RULES_PATH, 'wb') as fd:
            fd.write(r.content)
        print("> Download completed.")
    if not isfile(YARA_COMPILED_PATH):
        yara.compile(filepath=YARA_RULES_PATH).save(YARA_COMPILED_PATH)
    return yara.load(YARA_COMPILED_PATH)


def recursive_files_listing(folder: str) -> List:
    assert isdir(folder)
    return [join(root, f) for root, _, files in os.walk(folder, topdown=False) for f in files]


def rules_match(tgt_file: str):
    matches = RULES.match(tgt_file)
    matching_rules = list()  #[m.rule for m in matches]
    for m in matches:
        for s in m.strings:
            matching_rules.append(f'{m.rule}({s[1]})@{hex(s[0])}')
    if len(matching_rules) <= 0:
        return None
    return {tgt_file: matching_rules}


def main(tgt_folder: str, parallel: bool = True) -> List[Dict]:
    print('> Recursively scanning input directory...')
    files = recursive_files_listing(tgt_folder)
    print(f'> Found {len(files)} files. Analysis in progress...')
    if parallel:
        with Pool(processes=3) as pool:
            outputs = list(tqdm(pool.imap(rules_match, files), total=len(files)))
    else:
        outputs = [rules_match(f) for f in files]
    print(f'> Analyzed {len(outputs)} files')
    return list(filter(None, outputs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='findcrypt-PYara')
    parser.add_argument('-d', '--dir', type=str, help='Target directory', required=True)
    parser.add_argument('-o', '--out', type=str, help='Output JSON file', required=True)
    args = parser.parse_args()
    tgt_dir = args.dir
    assert isdir(tgt_dir)
    tgt_file = args.out
    if isfile(tgt_file):
        sys.exit(f'> File {tgt_file} already exists. Exiting...')

    RULES = yara_files_check_n_load()
    results = main(tgt_dir)
    with open(tgt_file, 'w') as fp:
        json.dump(results, fp)
