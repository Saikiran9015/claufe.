#!/usr/bin/env python3
"""
Migration helper for banners collection.
- Scans documents and normalizes fields so templates can use direct links:
  - sets `image_file_path` when the file exists under `uploads/`
  - preserves `image` when it's a data URI or external URL
  - sets `image_filename` to the best candidate for backward compatibility

Usage:
  python scripts/migrate_banners.py        # dry-run, prints planned updates
  python scripts/migrate_banners.py --apply  # apply updates to DB

Be careful: this updates MongoDB documents. Run dry-run first.
"""

import os
import sys
import argparse
from pymongo import MongoClient
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, '.env'))

MONGO_URL = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
DB_NAME = os.getenv('MONGO_DB_NAME', 'dreamx')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')

client = MongoClient(MONGO_URL)
db = client[DB_NAME]
banners_col = db['banners']


def find_in_uploads(filename):
    """Search uploads/ for a file with name `filename` and return the relative path if found."""
    for root, dirs, files in os.walk(UPLOADS_DIR):
        for f in files:
            if f == filename:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, UPLOADS_DIR).replace('\\', '/')
                return rel
    return None


def plan_update(doc):
    # examine fields in order of preference
    src_candidates = [doc.get('image'), doc.get('image_file_path'), doc.get('image_filename')]
    chosen = None
    updates = {}

    for src in src_candidates:
        if not src or not isinstance(src, str):
            continue
        s = src.strip()
        if s.startswith('data:'):
            # it's an embedded data URI; keep it in `image` and do not try to make file path
            updates['image'] = s
            updates['image_file_path'] = None
            updates['image_filename'] = s
            chosen = 'data'
            break
        if s.startswith('http://') or s.startswith('https://'):
            # external link; store in `image` so templates can use it directly
            updates['image'] = s
            updates['image_file_path'] = None
            updates['image_filename'] = s
            chosen = 'external'
            break
        # now treat it as a path or filename
        if '/' in s:
            # path-like: check if file exists under uploads
            candidate_full = os.path.join(UPLOADS_DIR, s)
            if os.path.exists(candidate_full):
                updates['image_file_path'] = s.replace('\\', '/')
                updates['image_filename'] = s.replace('\\', '/')
                updates['image'] = None
                chosen = 'path_exists'
                break
            else:
                # path doesn't exist; try search for filename portion
                base = os.path.basename(s)
                found = find_in_uploads(base)
                if found:
                    updates['image_file_path'] = found
                    updates['image_filename'] = found
                    updates['image'] = None
                    chosen = 'found_by_name'
                    break
                else:
                    # keep as filename for now
                    updates['image_filename'] = s
                    updates['image_file_path'] = None
                    updates['image'] = None
                    chosen = 'unknown_path'
                    break
        else:
            # just a filename — search uploads
            found = find_in_uploads(s)
            if found:
                updates['image_file_path'] = found
                updates['image_filename'] = found
                updates['image'] = None
                chosen = 'found_by_name'
                break
            else:
                # no file found — keep as filename in image_filename
                updates['image_filename'] = s
                updates['image_file_path'] = None
                updates['image'] = None
                chosen = 'not_found'
                break

    # if nothing found at all, do nothing
    if not updates:
        return None, None

    # cleanup: ensure keys exist (explicitly set None where needed)
    for k in ('image', 'image_file_path', 'image_filename'):
        if k not in updates:
            updates[k] = doc.get(k, None)

    return updates, chosen


def main(apply=False):
    total = banners_col.count_documents({})
    print(f'Found {total} banner documents')

    changed = 0
    for doc in banners_col.find():
        updates, reason = plan_update(doc)
        if not updates:
            continue
        # determine if update necessary
        needs_update = False
        set_obj = {}
        for k, v in updates.items():
            cur = doc.get(k)
            # normalize None vs missing
            if cur is None and v is None:
                continue
            if cur != v:
                set_obj[k] = v
                needs_update = True
        if not needs_update:
            continue

        changed += 1
        print('---')
        print('Doc _id:', doc.get('_id'))
        print('Reason:', reason)
        print('Planned updates:')
        for k, v in set_obj.items():
            print(' ', k, '->', v)

        if apply:
            banners_col.update_one({'_id': doc['_id']}, {'$set': set_obj})
            print('Applied')

    print('---')
    print(f'Planned/Applied updates: {changed}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='Apply changes to database')
    args = parser.parse_args()
    main(apply=args.apply)
