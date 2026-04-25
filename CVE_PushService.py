# coding=utf-8
import sys
from pkg.utils import *
import requests
import json
import os
import gzip
import io
import sqlite3
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from serverchan_sdk import sc_send

# 基本配置
SCKEY = os.getenv("SCKEY")
DB_PATH = 'vulns.db'  # 数据库文件路径
LOG_FILE = 'cveflows.log'  # 日志文件前缀
CVSS_THRESHOLD = 7.0  # 只关注CVSS>=7.0的高危漏洞

# 日志配置
logger = logging.getLogger("CVEFlows")
logger.setLevel(logging.INFO)

# 控制台输出
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 文件轮转输出：每天生成一个日志，保留 7 天
file_handler = TimedRotatingFileHandler(
    LOG_FILE, when="midnight", interval=1, backupCount=7, encoding="utf-8"
)
file_handler.setLevel(logging.INFO)

# 日志格式
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# 初始化数据库
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vulns
                 (id TEXT PRIMARY KEY, 
                  published_date TEXT, 
                  cvss_score REAL, 
                  description TEXT, 
                  vector_string TEXT,
                  refs TEXT,
                  source TEXT)''')
    conn.commit()
    conn.close()

# 从NVD获取CVE数据
def fetch_nvd_data(use_recent=True):
    if use_recent:
        url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
    else:
        year = get_current_year()
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

    try:
        logger.info(f"Fetching data from: {url}")
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()

        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz_file:
            data = json.loads(gz_file.read().decode('utf-8'))
            return data.get('vulnerabilities', [])
    except Exception as e:
        logger.error(f"Failed to fetch NVD data: {str(e)}")
        return []


# 检查漏洞是否在最近24小时内发布
def parse_nvd_datetime(published_date_str):
    normalized = published_date_str.strip()
    parsed_dt = datetime.fromisoformat(normalized)
    if parsed_dt.tzinfo is not None:
        return parsed_dt.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed_dt


def is_recent(published_date_str):
    try:
        published_dt = parse_nvd_datetime(published_date_str)
        time_diff = datetime.utcnow() - published_dt
        return time_diff.total_seconds() <= 24 * 3600
    except Exception as e:
        logger.error(f"Failed to parse date {published_date_str}: {str(e)}")
        return False

# 解析CVE条目，提取关键信息
def parse_cve_item(cve_item):
    try:
        cve_data = cve_item['cve']
        cve_id = cve_data.get('id', 'UNKNOWN')
        published_date = cve_data['published']

        if not is_recent(published_date):
            logger.debug(f"Skipping {cve_id} as it's not recent ({published_date})")
            return None

        description = next((desc['value'] for desc in cve_data.get('descriptions', [])
                               if desc.get('lang') == 'en'), "No description available")

        cvss_score = 0.0
        vector_string = "N/A"

        if 'metrics' in cve_data:
            if 'cvssMetricV31' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")
            elif 'cvssMetricV30' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")
            elif 'cvssMetricV2' in cve_data['metrics']:
                cvss_data = cve_data['metrics']['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                vector_string = cvss_data.get('vectorString', "N/A")

        if cvss_score < CVSS_THRESHOLD:
            return None

        refs = "\n".join([ref.get('url', '') for ref in cve_data.get('references', [])][:3])

        return {
            'id': cve_id,
            'published_date': cve_data.get('published', 'N/A'),
            'cvss_score': cvss_score,
            'description': description,
            'vector_string': vector_string,
            'refs': refs,
            'source': 'NVD'
        }
    except KeyError as e:
        logger.error(f"Error parsing CVE item: missing key {str(e)}")
        return None

# 检查是否是新漏洞
def is_new_vuln(vuln_info):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM vulns WHERE id=?", (vuln_info['id'],))
    exists = c.fetchone() is not None
    conn.close()
    return not exists

# 保存漏洞信息到数据库
def save_vuln(vuln_info):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO vulns VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (vuln_info['id'], vuln_info['published_date'], vuln_info['cvss_score'],
                   vuln_info['description'], vuln_info['vector_string'],
                   vuln_info['refs'], vuln_info['source']))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

# 通过Server酱发送通知
def send_notification(vuln_info, template: str, delaytime: int):

    if delaytime > 0:
        logger.info(f"Wait {delaytime} seconds before sending the notification. ...")
        time.sleep(delaytime)


    message = template.format(
        cve_id=vuln_info['id'],
        cvss_score=vuln_info['cvss_score'],
        published_date=vuln_info['published_date'],
        vector_string=vuln_info['vector_string'],
        description=translate(vuln_info['description'], 3),
        url=vuln_info['refs'],
        source=vuln_info['source']
    )

    title = f"高危漏洞: {vuln_info['id']} ({vuln_info['cvss_score']})"

    try:
        response = sc_send(SCKEY, title, message, {"tags": "🚨漏洞警报"})
        logger.info(f"Notification sent for {vuln_info['id']}, response: {response}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")


def main():
    logger.info("Starting CVE monitoring...")

    init_db()

    # 加载template目录下的nvd_cve.md模板
    template_path = os.path.join(os.path.dirname(__file__), 'template', 'nvd_cve.md')
    template = load_template(template_path)

    logger.info("Fetching recent CVE data...")
    cve_items = fetch_nvd_data(use_recent=True)

    if not cve_items:
        logger.warning("Failed to fetch recent data, trying full year data...")
        cve_items = fetch_nvd_data(use_recent=False)

    if not cve_items:
        logger.error("Failed to fetch any CVE data. Exiting.")
        return 0

    logger.info(f"Found {len(cve_items)} CVE items")

    new_vulns = 0
    new_ids = []
    for item in cve_items:
        vuln_info = parse_cve_item(item)
        if vuln_info and is_new_vuln(vuln_info):
            logger.info(f"[INFO] New high-risk vulnerability found: {vuln_info['id']}")
            save_vuln(vuln_info)
            send_notification(vuln_info,template,3)
            new_vulns += 1
            new_ids.append(vuln_info['id'])

    logger.info(f"[INFO] Monitoring completed. Found {new_vulns} new vulnerabilities.")

    if new_vulns > 0:
        with open("new_vulns.flag", "w") as f:
            f.write(f"{new_vulns}\n")
            f.write("\n".join(new_ids))

    return 0

if __name__ == '__main__':
    sys.exit(main())
