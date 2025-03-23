from werkzeug.security import generate_password_hash
from datetime import datetime
from models import db, User

def create_staff_user(username, password, nickname):
    """
    创建员工账号
    :param username: 用户名
    :param password: 密码
    :param nickname: 昵称
    :return: User对象
    """
    try:
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"用户名 {username} 已存在")
            return None
            
        # 创建新员工账号
        new_staff = User(
            username=username,
            password=generate_password_hash(password),
            nickname=nickname,
            role='STAFF',
            status=1,
            user_type=2,
            created_at=datetime.now()
        )
        
        # 保存到数据库
        db.session.add(new_staff)
        db.session.commit()
        
        print(f"成功创建员工账号 - 用户名: {username}, 昵称: {nickname}")
        return new_staff
        
    except Exception as e:
        print(f"创建员工账号失败: {str(e)}")
        db.session.rollback()
        return None

if __name__ == '__main__':
    # 示例：创建员工账号
    staff = create_staff_user(
        username='staff001',
        password='staff123456',  # 请修改为安全的密码
        nickname='员工小王'
    )
    
    if staff:
        print(f"员工账号创建成功 - ID: {staff.id}")
    else:
        print("员工账号创建失败") 