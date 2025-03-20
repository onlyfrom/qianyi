import os

# 是否开启debug模式
DEBUG = True

# 数据库配置
username = os.environ.get("MYSQL_USERNAME", "root")
password = os.environ.get("MYSQL_PASSWORD", "beibei&395")
db_address = os.environ.get("MYSQL_ADDRESS", "sh-cynosdbmysql-grp-kbj3s1h8.sql.tencentcdb.com:25481")
database = os.environ.get("MYSQL_DATABASE", "qyflask")

# 数据库连接池配置
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_POOL_SIZE = 10
SQLALCHEMY_MAX_OVERFLOW = 20
SQLALCHEMY_POOL_TIMEOUT = 10
SQLALCHEMY_POOL_RECYCLE = 1800

# 微信小程序配置
APPID = os.environ.get("APPID", "wxa17a5479891750b3")
SECRET = os.environ.get("SECRET", "33359853cfee1dc1e2b6e535249e351d")
CLOUD_ENV_ID = os.environ.get("CLOUD_ENV_ID", "prod-9gd4jllic76d4842")

# JWT配置
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "onlyfrom")
JWT_EXPIRE_HOURS = 24 * 7  # Token 过期时间（小时）

# 文件上传配置
UPLOAD_FOLDER = "uploads"
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max-limit
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# 系统配置
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT_MINUTES = 30

# 跨域配置
CORS_ORIGINS = ["*"]
CORS_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = ["Content-Type", "Authorization"]
CORS_MAX_AGE = 600

# 日志配置
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = "logs/app.log"
