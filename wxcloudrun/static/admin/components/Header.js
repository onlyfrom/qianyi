export default {
    template: `
        <el-header>
            <div class="header-title">仟艺服饰后台管理系统</div>
            <div class="user-info">
                <el-dropdown @command="handleCommand">
                    <span class="el-dropdown-link">
                        <el-avatar :size="32" :src="userInfo.avatar"></el-avatar>
                        <span style="margin-left: 8px">{{ userInfo.nickname || userInfo.username }}</span>
                        <el-icon class="el-icon--right"><arrow-down /></el-icon>
                    </span>
                    <template #dropdown>
                        <el-dropdown-menu>
                            <el-dropdown-item command="profile">个人信息</el-dropdown-item>
                            <el-dropdown-item command="logout">退出登录</el-dropdown-item>
                        </el-dropdown-menu>
                    </template>
                </el-dropdown>
            </div>
        </el-header>
    `,
    data() {
        return {
            userInfo: JSON.parse(localStorage.getItem('userInfo') || '{}')
        }
    },
    methods: {
        handleCommand(command) {
            if (command === 'logout') {
                this.handleLogout();
            } else if (command === 'profile') {
                this.$emit('show-profile');
            }
        },
        handleLogout() {
            localStorage.removeItem('token');
            localStorage.removeItem('userInfo');
            window.location.href = '/admin/index.html';
        }
    }
} 