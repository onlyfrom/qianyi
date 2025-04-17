from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
import pymysql
import logging
import os
import config
import warnings

# 忽略 SQLAlchemy 的废弃警告
warnings.filterwarnings('ignore', category=Warning)

# 因MySQLDB不支持Python3，使用pymysql扩展库代替MySQLDB库
pymysql.install_as_MySQLdb()

# 初始化web应用
app = Flask(__name__, instance_relative_config=True)

# 加载配置
app.config.from_object('config')

# 设定数据库链接
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{}:{}@{}/{}'.format(
    config.username, config.password, config.db_address, config.database
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = config.SQLALCHEMY_POOL_SIZE
app.config['SQLALCHEMY_MAX_OVERFLOW'] = config.SQLALCHEMY_MAX_OVERFLOW
app.config['SQLALCHEMY_POOL_TIMEOUT'] = config.SQLALCHEMY_POOL_TIMEOUT
app.config['SQLALCHEMY_POOL_RECYCLE'] = config.SQLALCHEMY_POOL_RECYCLE

# 初始化DB操作对象
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 配置跨域
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept"],
        "supports_credentials": True
    }
})

# 配置日志
if not os.path.exists('logs'):
    os.makedirs('logs')

# 创建日志处理器
file_handler = logging.FileHandler(config.LOG_FILE)
console_handler = logging.StreamHandler()

# 设置日志格式
formatter = logging.Formatter(config.LOG_FORMAT)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 获取根日志记录器
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, config.LOG_LEVEL))

# 添加处理器
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# 设置Flask应用的日志处理器
app.logger.handlers = []
app.logger.addHandler(file_handler)
app.logger.addHandler(console_handler)
app.logger.setLevel(getattr(logging, config.LOG_LEVEL))

# 全局错误处理
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'code': 404, 'message': '请求的资源不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'code': 500, 'message': '服务器内部错误'}), 500

@app.errorhandler(Exception)
def unhandled_exception(error):
    app.logger.error('Unhandled Exception: %s', str(error))
    return jsonify({'code': 500, 'message': '服务器内部错误'}), 500

# 请求日志记录
@app.before_request
def log_request_info():
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())

# CORS预检请求处理
@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    response = jsonify({'status': 'ok'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

# 导入视图函数
from . import views
from . import stock_import
from . import billing

# 注册蓝图
app.register_blueprint(billing.billing_bp)

