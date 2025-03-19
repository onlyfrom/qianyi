# 创建应用实例
import sys
import logging
from wxcloudrun import app, db

# 配置日志
logger = logging.getLogger(__name__)

try:
    # 初始化数据库
    with app.app_context():
        db.create_all()
        logger.info("数据库表初始化成功")
except Exception as e:
    logger.error(f"数据库初始化失败: {str(e)}")
    sys.exit(1)

# 打印所有注册的路由
def list_routes():
    logger.info("注册的路由列表:")
    for rule in app.url_map.iter_rules():
        logger.info(f"路由: {rule.rule} [方法: {', '.join(rule.methods)}]")

# 启动Flask Web服务
if __name__ == '__main__':
    try:
        # 打印路由列表
        list_routes()
        
        host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
        logger.info(f"启动服务器 http://{host}:{port}")
        app.run(host=host, port=port)
    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        sys.exit(1)
