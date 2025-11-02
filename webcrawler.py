# ...existing code...
import os
import re
import time
import json
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from tqdm import tqdm
from dotenv import load_dotenv

# Simple crawler to download documents from a site and its subpages.
# Usage (from VS Code terminal):
# python webcrawler.py "www.caiso.com/generation-transmission/generation" --depth 2 --outdir downloads

DOWNLOAD_DIR = "downloads_103125"
USER_AGENT = "Mozilla/5.0 (compatible; PowerNOVA-Crawler/1.0)"
ALLOWED_EXT = {".pdf", ".docx", ".doc", ".txt", ".rtf"}
REQUEST_TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.2
INDEX_FILENAME = "download_index.json"
AZURE_STORAGE_SHARE = "crawldocs"
AZURE_DOCS_DIRECTORY = "docs"

os.makedirs(DOWNLOAD_DIR, exist_ok=True)

load_dotenv()

def get_azure_client():
    conn_str = os.getenv("POWERNOVA_AZURE_STORAGE_CONNECTION_STRING")

    if conn_str == "" or conn_str == None:
        return None

    service = ShareServiceClient.from_connection_string(conn_str=conn_str)
    shares = service.get_share_client(AZURE_STORAGE_SHARE) 
    crawl_client = shares.get_directory_client(AZURE_DOCS_DIRECTORY)
    #crawl_client.create_directory()
    return crawl_client

def upload_to_azure(path, name):
    try:
        client = get_azure_client()
        if client != None:
            # Upload a file to the directory
            print("File path: {}".format(path))
            with open(path, "rb") as source:
                print("Uploading to azure: {}".format(name))
                content = source.read()
                client.upload_file(file_name=name, data=content)
    except:
        return False
    return True

def is_html_response(resp):
    ct = resp.headers.get("Content-Type", "")
    return "text/html" in ct


def safe_filename_from_url(url, resp=None):
    # Prefer Content-Disposition filename
    if resp is not None:
        cd = resp.headers.get("content-disposition")
        if cd:
            m = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', cd, flags=re.I)
            if m:
                return os.path.basename(m.group(1))
    # Fallback to parsed path
    path = urlparse(url).path
    name = os.path.basename(path) or "download"
    return name


def _load_index(out_dir):
    idx_path = os.path.join(out_dir, INDEX_FILENAME)
    if os.path.exists(idx_path):
        try:
            with open(idx_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def _save_index(index, out_dir):
    idx_path = os.path.join(out_dir, INDEX_FILENAME)
    try:
        with open(idx_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2)
    except Exception as e:
        print("Unable to save index:", e)


def download_url(url, out_dir=DOWNLOAD_DIR, session=None, index=None):
    """
    Download a URL to out_dir. If index (dict) provided and URL is already recorded
    and the file exists, skip downloading and return existing path.
    The index will be updated on successful download.
    """
    session = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}

    # If index says we've already downloaded this URL and file exists, skip.
    if index is not None:
        entry = index.get(url)
        if entry:
            existing_path = os.path.join(out_dir, entry.get("filename", ""))
            if existing_path and os.path.exists(existing_path):
                return existing_path

    try:
        with session.get(url, stream=True, timeout=REQUEST_TIMEOUT, headers=headers) as r:
            if r.status_code != 200:
                return None
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            fname = safe_filename_from_url(url, r)
            # ensure extension exists
            if not os.path.splitext(fname)[1] and ext:
                fname = fname + ext

            # Avoid filename collision: if file exists but not from this URL, append counter
            out_path = os.path.join(out_dir, fname)
            if os.path.exists(out_path):
                # If index shows a different URL mapped to this filename, find a unique name
                if index is not None and any(v.get("filename") == fname and u != url for u, v in index.items()):
                    base, extension = os.path.splitext(fname)
                    counter = 1
                    while True:
                        candidate = f"{base}_{counter}{extension}"
                        cand_path = os.path.join(out_dir, candidate)
                        if not os.path.exists(cand_path):
                            out_path = cand_path
                            fname = candidate
                            break
                        counter += 1
                else:
                    # existing file likely the same; return existing path
                    if index is not None:
                        return out_path
                    # if no index, still return existing path to avoid re-download
                    return out_path

            with open(out_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            if upload_to_azure(out_path, fname):
                print("Removing file: {}".format(out_path))
                os.remove(out_path)
            # Update index if present
            if index is not None:
                index[url] = {
                    "filename": fname,
                    "path": out_path,
                    "size": os.path.getsize(out_path)
                }
                _save_index(index, out_dir)

            return out_path
    except Exception as e:
        print(f"Download error {url}: {e}")
        return None


def fetch_page_text(url, session=None):
    session = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        if r.status_code == 200 and is_html_response(r):
            return r.text, r.url
    except Exception as e:
        # print(f"Fetch error {url}: {e}")
        return None, None
    return None, None


def extract_links(html, base_url):
    # Lightweight link extraction without BeautifulSoup to avoid extra deps
    # Only returns absolute URLs
    links = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, flags=re.I):
        raw = m.group(1).strip()
        if raw.startswith("javascript:") or raw.startswith("mailto:"):
            continue
        absu = urljoin(base_url, raw)
        links.add(absu)
    return links


def same_domain(url1, url2):
    return urlparse(url1).netloc == urlparse(url2).netloc


def is_document_link(url):
    path = urlparse(url).path.lower()
    for ext in ALLOWED_EXT:
        if path.endswith(ext):
            return True
    return False


def crawl_and_download(start_url, depth=2, max_pages=500, out_dir=DOWNLOAD_DIR, polite=True):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    q = deque()
    q.append((start_url, 0))
    visited = set()
    downloaded = []
    pages_visited = 0

    # load existing index to avoid re-downloading
    index = _load_index(out_dir)

    while q and pages_visited < max_pages:
        url, d = q.popleft()
        if url in visited or d > depth:
            continue
        visited.add(url)

        html, final_url = fetch_page_text(url, session=session)
        pages_visited += 1

        if html:
            links = extract_links(html, final_url or url)
            # First download any document links on this page
            doc_links = [l for l in links if is_document_link(l) and same_domain(start_url, l)]
            for doc in tqdm(doc_links, desc=f"Downloading docs from {url}", leave=False):
                path = download_url(doc, out_dir=out_dir, session=session, index=index)
                if path:
                    downloaded.append(path)
                    time.sleep(SLEEP_BETWEEN_REQUESTS)

            # Enqueue same-domain html links for further crawling
            for l in links:
                if same_domain(start_url, l) and not is_document_link(l):
                    # Only add HTML-like links (heuristic)
                    if urlparse(l).scheme in ("http", "https"):
                        q.append((l, d + 1))

        else:
            # If page was not HTML, but is a doc link itself, try to download directly
            if is_document_link(url) and same_domain(start_url, url):
                path = download_url(url, out_dir=out_dir, session=session, index=index)
                if path:
                    downloaded.append(path)

        if polite:
            time.sleep(SLEEP_BETWEEN_REQUESTS)

    # save index at end (in case any downloads occurred)
    _save_index(index, out_dir)
    return downloaded

from azure.storage.fileshare import ShareServiceClient

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Crawl a site and download documents (.pdf .docx .doc .txt).")
    parser.add_argument("--start_url", default="https://www.caiso.com/generation-transmission/generation", help="Starting URL to crawl")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2)")
    parser.add_argument("--outdir", default=DOWNLOAD_DIR, help="Download directory")
    parser.add_argument("--max-pages", type=int, default=500, help="Max pages to visit")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    start = args.start_url
    print(f"Starting crawl: {start} (depth={args.depth}) -> {args.outdir}")
    files = crawl_and_download(start, depth=args.depth, max_pages=args.max_pages, out_dir=args.outdir)
    print(f"\nFinished. Downloaded {len(files)} files:")
    for f in files:
       print(" -", f)


if __name__ == "__main__":
    main()
# ...existing code...