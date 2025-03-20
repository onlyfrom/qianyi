# 创建应用实例
import sys
import logging
import os
import traceback
from wxcloudrun import app, db

# 配置日志
logger = logging.getLogger(__name__)

def init_database():
    try:
        # 确保实例目录存在
        if not os.path.exists('instance'):
            os.makedirs('instance')
            logger.info("创建实例目录成功")

        # 初始化数据库
        with app.app_context():
            db.create_all()
            logger.info("数据库表初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {str(e)}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        sys.exit(1)

# 打印所有注册的路由
def list_routes():
    try:
        logger.info("注册的路由列表:")
        for rule in app.url_map.iter_rules():
            logger.info(f"路由: {rule.rule} [方法: {', '.join(rule.methods)}]")
    except Exception as e:
        logger.error(f"打印路由列表失败: {str(e)}")

# 启动Flask Web服务
if __name__ == '__main__':
    try:
        # 初始化数据库
        init_database()
        
        # 打印路由列表
        list_routes()
        
        # 获取主机和端口
        host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
        
        # 启动服务器
        logger.info(f"启动服务器 http://{host}:{port}")
        app.run(host=host, port=port)
    except Exception as e:
        logger.error(f"服务启动失败: {str(e)}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        sys.exit(1)
