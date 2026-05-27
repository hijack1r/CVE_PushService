import os
import sqlite3
import json
import re
import datetime
import time
from pkg.utils import *
from typing import List, Dict, Optional
import logging
from serverchan_sdk import sc_send

# 获取环境变量
SCKEY = os.getenv("SCKEY")
GH_TOKEN = os.getenv('GH_TOKEN')
DB_PATH = "Github_CVE_Monitor.db"
LOG_FILE = 'Ghflows.log'  # 日志文件前缀
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

# 日志配置
logger = logging.getLogger("Ghflows")
logger.setLevel(logging.INFO)

# 加载黑名单配置
def load_blacklist():
    """从外部 JSON 文件加载黑名单"""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs", "blacklist.json"), "r") as file:
            blacklist = json.load(file)
        return blacklist
    except Exception as e:
        logger.error(f"Error loading blacklist: {str(e)}")
        return {
            "urls": [],
            "full_names": [],
            "repo_ids": []
        }

BLACKLIST = load_blacklist()

def init_db():
    """初始化数据库，创建必要的表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 创建仓库信息表
    c.execute('''CREATE TABLE IF NOT EXISTS repositories
                 (
                     id INTEGER PRIMARY KEY,
                     name TEXT,
                     description TEXT,
                     url TEXT,
                     pushed_at TEXT,
                     created_at TEXT,
                     updated_at TEXT,
                     cve_ids TEXT,
                     status TEXT
                 )''')

    # 创建检查记录表
    c.execute('''CREATE TABLE IF NOT EXISTS check_records
                 (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     check_time TEXT,
                     total_count INTEGER
                 )''')

    conn.commit()
    conn.close()


def save_or_update_repository(repo_info: Dict, status: str = 'new'):
    """保存新仓库或更新已存在的仓库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # 先检查是否存在
        c.execute("SELECT id FROM repositories WHERE id = ?", (repo_info['id'],))
        exists = c.fetchone()

        if exists:
            # 更新已存在的记录
            c.execute("""UPDATE repositories
                         SET name        = ?,
                             description = ?,
                             url         = ?,
                             pushed_at   = ?,
                             updated_at  = ?,
                             cve_ids     = ?,
                             status      = ?
                         WHERE id = ?""",
                      (repo_info['name'], repo_info['description'],
                       repo_info['url'], repo_info['pushed_at'],
                       repo_info['updated_at'], ','.join(repo_info['cve_ids']),
                       status, repo_info['id']))
            logger.info(f"Updated repository {repo_info['id']} with status: {status}")
        else:
            # 插入新记录
            c.execute("INSERT INTO repositories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (repo_info['id'], repo_info['name'], repo_info['description'],
                       repo_info['url'], repo_info['pushed_at'], repo_info['created_at'],
                       repo_info['updated_at'], ','.join(repo_info['cve_ids']), status))
            logger.info(f"Inserted new repository {repo_info['id']} with status: {status}")

        conn.commit()
    except Exception as e:
        logger.error(f"Error saving/updating repository {repo_info['id']}: {str(e)}")
    finally:
        conn.close()

def repository_exists_with_status(repo_id: int) -> Optional[tuple]:
    """检查仓库是否存在并返回其状态信息"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, updated_at, status FROM repositories WHERE id = ?", (repo_id,))
    result = c.fetchone()
    conn.close()
    return result

def is_blacklisted(repo_info: Dict) -> bool:
    """检查仓库是否在黑名单中"""
    repo_url = repo_info.get('url', '')
    full_name = repo_info.get('full_name', '')
    repo_id = repo_info.get('id')

    # 检查仓库ID
    if repo_id and repo_id in BLACKLIST["repo_ids"]:
        return True

    # 检查仓库全名 (owner/repo)
    if full_name:
        for blacklisted_name in BLACKLIST["full_names"]:
            if blacklisted_name.lower() == full_name.lower():
                return True

    # 检查仓库URL（支持完整匹配或部分匹配）
    if repo_url:
        repo_url_lower = repo_url.lower().rstrip('/')
        for blacklisted_url in BLACKLIST["urls"]:
            blacklisted_url_lower = blacklisted_url.lower().rstrip('/')
            # 精确匹配或包含匹配
            if repo_url_lower == blacklisted_url_lower or blacklisted_url_lower in repo_url_lower:
                return True

    return False

def save_check_record(total_count: int):
    """保存检查记录"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO check_records (check_time, total_count) VALUES (?, ?)",
              (datetime.now().isoformat(), total_count))
    conn.commit()
    conn.close()

def get_last_total_count() -> int:
    """获取上次检查的总数"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT total_count FROM check_records ORDER BY id DESC LIMIT 1")
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0

def extract_cve_ids(text: str) -> List[str]:
    """从任意文本中提取 CVE 标识列表（去重，返回大写）"""
    if not text:
        return []
    found = CVE_REGEX.findall(text)
    normalized = sorted({f.upper() for f in found})
    return normalized

def fetch_github_repositories() -> Optional[Dict]:
    """从GitHub API获取CVE相关仓库"""
    year = get_current_year()
    api_url = f"https://api.github.com/search/repositories?q=CVE-{year}&sort=updated&order=desc"
    # 仅在提供 GH_TOKEN 时添加认证头，避免无效的 Bearer None 导致 401
    headers = {}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch data from GitHub: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None

def process_new_repositories() -> List[Dict]:
    """处理新仓库并返回新发现的仓库列表"""
    data = fetch_github_repositories()
    if not data or "items" not in data:
        logger.error("No valid data response from GitHub API")
        return []

    current_total = data["total_count"]
    last_total = get_last_total_count()

    # 保存本次检查记录
    save_check_record(current_total)

    if current_total <= last_total:
        logger.info("No new repositories found")
        return []

    new_repositories = []
    for repo in data["items"]:
        repo_id = repo["id"]
        repo_info = {
            "id": repo_id,
            "name": repo["name"],
            "full_name": repo.get("full_name", ""),
            "description": repo.get("description","This project warehouse is not described."),
            "url": repo["html_url"],
            "pushed_at": repo["pushed_at"],
            "created_at": repo["created_at"],
            "updated_at": repo["updated_at"],
            "cve_ids": extract_cve_ids(repo.get("description", "")or repo.get("name", ""))
        }

        # 检查是否在黑名单中
        if is_blacklisted(repo_info):
            logger.info(f"Repository {repo_info['url']} is in blacklist, skipping...")
            continue

        # 处理新仓库和已更新仓库
        existing_repo = repository_exists_with_status(repo_id)

        if existing_repo:
            existing_id, existing_updated_at, existing_status = existing_repo
            if existing_updated_at < repo_info['updated_at']:
                # 仓库有更新，标记为"updated"
                logger.info(f"Repository {repo_info['url']} has been updated.")
                save_or_update_repository(repo_info, status="updated")

        else:
            # 新仓库
            save_or_update_repository(repo_info, status="new")
            new_repositories.append(repo_info)
            logger.info(f"New repository found: {repo_info['url']}")

        if len(new_repositories) >= 10:
            break

    return new_repositories

def send_notification(repo_info: Dict, template: str, delaytime: int):
    """发送单个仓库的通知"""

    if delaytime > 0:
        logger.info(f"Wait {delaytime} seconds before sending the notification. ...")
        time.sleep(delaytime)

    # 获取 CVE 概述
    cve_overviews = []
    for cve_id in repo_info['cve_ids']:
        overview = get_cve_overview(cve_id)
        cve_overviews.append(overview)

    # 使用模板替换参数 添加CVE概述
    # cve_overviews_text = "\n\n".join(cve_overviews)
    message = template.format(
        name=repo_info['name'],
        cve_ids=', '.join(repo_info['cve_ids']) if repo_info['cve_ids'] else '未检测到CVE ID',
        pushed_at=repo_info['pushed_at'],
        created_at=repo_info['created_at'],
        description=translate(repo_info['description'],5),
        url=repo_info['url'],
        cve_overviews=', '.join(repo_info['cve_ids']) + ':\n\n' + translate('\n'.join(cve_overviews), 6) if repo_info.get(
            'cve_ids') else '未找到该漏洞概述'
    )

    title = f"漏洞仓库: {repo_info['name']}"

    try:
        response = sc_send(SCKEY, title, message, {"tags": "🧰Possible poc/exp"})
        logger.info(f"Notification sent for repository: {repo_info['name']}, response: {response}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")

def main():
    """主函数"""
    # 初始化数据库
    init_db()

    # 加载template目录下的github_repo.md模板
    template_path = os.path.join(os.path.dirname(__file__), 'template', 'github_repo.md')
    template = load_template(template_path)

    # 处理新仓库
    new_repos = process_new_repositories()

    # 发送通知
    for repo in new_repos:
        send_notification(repo,template,3)

if __name__ == "__main__":
    main()
