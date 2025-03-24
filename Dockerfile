# 二开推荐阅读[如何提高项目构建效率](https://developers.weixin.qq.com/miniprogram/dev/wxcloudrun/src/scene/build/speed.html)
# 选择基础镜像。如需更换，请到[dockerhub官方仓库](https://hub.docker.com/_/python?tab=tags)自行选择后替换。
# 已知alpine镜像与pytorch有兼容性问题会导致构建失败，如需使用pytorch请务必按需更换基础镜像。
FROM python:3.8-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 安装系统依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制项目文件
COPY . .

# 安装 Python 依赖
RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ --upgrade pip && \
    pip install -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt

# 创建必要的目录
RUN mkdir -p logs uploads

# debian/ubuntu
RUN apt install ca-certificates -y
# 暴露端口。
# 此处端口必须与「服务设置」-「流水线」以及「手动上传代码包」部署时填写的端口一致，否则会部署失败。
EXPOSE 80

# Python requests 指定环境变量
# Java 手动导入根证书
RUN keytool -importcert -file /app/cert/certificate.crt -alias apiweixin -keystore $JAVA_HOME/jre/lib/security/cacerts

# Node 指定根证书环境变量
ENV NODE_EXTRA_CA_CERTS=/app/cert/certificate.crt

# Python requests 指定环境变量
ENV REQUESTS_CA_BUNDLE=/app/cert/certificate.crt
# 执行启动命令
# 写多行独立的CMD命令是错误写法！只有最后一行CMD命令会被执行，之前的都会被忽略，导致业务报错。
# 请参考[Docker官方文档之CMD命令](https://docs.docker.com/engine/reference/builder/#cmd)
CMD ["python3", "run.py", "0.0.0.0", "80"]
