import datetime
import base64
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
# 假设 proxyUtil 在同级目录下
from proxyUtil import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_node_fingerprint(link):
    """
    生成节点的“指纹”，用于去重。
    指纹由 核心参数 组成 (如 IP:Port:UUID)，忽略备注名。
    """
    try:
        if link.startswith("vmess://"):
            # VMess 通常是 Base64 编码的 JSON
            b64 = link[8:]
            # 补全 padding，防止解码报错
            missing_padding = len(b64) % 4
            if missing_padding:
                b64 += '=' * (4 - missing_padding)
            
            try:
                info = json.loads(base64.b64decode(b64).decode('utf-8'))
                # 核心指纹: 地址:端口:用户ID
                return f"vmess://{info.get('add', 'err')}:{info.get('port', 'err')}:{info.get('id', 'err')}"
            except:
                return link # 解析失败退回原链接

        elif link.startswith(("vless://", "trojan://", "ss://", "ssr://")):
            # URL 格式，解析 hostname 和 port
            parsed = urllib.parse.urlparse(link)
            # 核心指纹: 协议://主机:端口/路径?参数 (去掉 # 后的备注)
            # 甚至可以更激进：只保留 netloc (IP:Port) 和 path
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        else:
            return link
    except Exception:
        return link

def deduplicate_nodes(nodes):
    """
    高级去重逻辑
    """
    unique_fingerprints = set()
    unique_nodes = []
    
    for node in nodes:
        node = node.strip()
        if not node: continue
        
        fingerprint = get_node_fingerprint(node)
        
        if fingerprint not in unique_fingerprints:
            unique_fingerprints.add(fingerprint)
            unique_nodes.append(node)
    
    logging.info(f"去重完成: 原有 {len(nodes)} 个，剩余 {len(unique_nodes)} 个")
    return unique_nodes

def process_subscription(line_data):
    """
    处理单个订阅链接的任务函数 (用于多线程)
    """
    url = line_data['url']
    line_content = line_data['line']
    
    # 1. 检查可用性
    status = False
    try:
        r = requests.head(url, timeout=5)
        if r.status_code // 100 == 2:
            status = True
    except:
        status = False
    
    status_icon = "✅" if status else "❌"
    
    # 2. 爬取节点
    nodes = []
    if status:
        try:
            nodes = ScrapURL(url)
        except Exception as e:
            logging.error(f"爬取失败 {url}: {e}")
            nodes = []
            
    # 3. 更新 Markdown 行内容 (正则替换状态和数量)
    # 原有的正则逻辑保持不变
    new_line = re.sub(r'^\|+?(.*?)\|+?(.*?)\|+?', f'| {status_icon} | {len(nodes)} |', line_content, count=1)
    
    return {
        "index": line_data['index'],
        "new_line": new_line,
        "nodes": nodes
    }

def main():
    # 1. 读取文件并准备任务
    tasks = []
    output_lines = [] # 占位符，用于保持文件顺序
    
    with open("nodes.md", encoding="utf8") as file:
        lines = file.readlines()
        
    cnt = 0
    for idx, line in enumerate(lines):
        line = line.rstrip()
        output_lines.append(line) # 默认先填入原行，稍后替换
        
        if line.startswith("|"):
            if cnt > 1: # 跳过表头
                parts = line.split('|')
                if len(parts) >= 3:
                    url = parts[-2].strip()
                    # 创建任务对象
                    tasks.append({
                        "index": idx,
                        "line": line,
                        "url": url
                    })
            cnt += 1

    logging.info(f"发现 {len(tasks)} 个订阅源，开始并发处理...")
    
    # 2. 多线程执行网络请求 (最大 10 线程)
    all_proxies = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        # 提交任务
        future_to_url = {executor.submit(process_subscription, task): task for task in tasks}
        
        for future in as_completed(future_to_url):
            try:
                result = future.result()
                # 更新文件行内容
                output_lines[result['index']] = result['new_line']
                # 收集节点
                all_proxies.extend(result['nodes'])
            except Exception as exc:
                logging.error(f"任务执行异常: {exc}")

    # 3. 写回 nodes.md
    with open("nodes.md", "w", encoding="utf8") as f:
        f.write('\n'.join(output_lines))

    # 4. 节点处理 (标签处理)
    TAGs = ["4FreeIran", "4Nika", "4Sarina", "4Jadi", "4Kian", "4Mohsen"]
    cur_tag = TAGs[datetime.datetime.now().hour % len(TAGs)]
    
    # 应用标签
    # 假设 tagsChanger 在 proxyUtil 中
    lines_with_tags = tagsChanger(all_proxies, cur_tag)
    
    # 5. 执行高级去重 (这是你最需要的部分)
    unique_lines = deduplicate_nodes(lines_with_tags)
    
    # 再次应用 tagsChanger (原脚本逻辑是去重后再搞一次，保留原逻辑)
    unique_lines = tagsChanger(unique_lines, cur_tag, True)

    # 6. 分类与保存
    categories = {
        "ss": "ss://",
        "ssr": "ssr://",
        "vmess": "vmess://",
        "vless": "vless://",
        "trojan": "trojan://"
    }
    
    # 保存所有
    with open('all', 'wb') as f:
        f.write(base64.b64encode('\n'.join(unique_lines).encode()))
        
    # 分类保存
    for name, prefix in categories.items():
        filtered = [s for s in unique_lines if s.startswith(prefix)]
        with open(name, 'wb') as f:
            f.write(base64.b64encode('\n'.join(filtered).encode()))
            
    logging.info("所有处理完成。")

if __name__ == "__main__":
    main()
