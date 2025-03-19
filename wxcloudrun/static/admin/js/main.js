const { createApp } = Vue
const { ElMessage } = ElementPlus
import axios from 'axios'

const app = createApp({
    data() {
        return {
            username: '',
            password: ''
        }
    },
    methods: {
        async handleLogin() {
            if (!this.username || !this.password) {
                ElMessage.warning('请输入用户名和密码')
                return
            }

            try {
                const response = await axios.post('/api/admin/login', {
                    username: this.username,
                    password: this.password
                })

                if (response.data.code === 0) {
                    ElMessage.success('登录成功')
                    localStorage.setItem('token', response.data.data.token)
                    window.location.href = '/admin/dashboard.html'
                } else {
                    ElMessage.error(response.data.msg || '登录失败')
                }
            } catch (error) {
                console.error('登录错误:', error)
                ElMessage.error('登录失败，请稍后重试')
            }
        }
    }
})

app.use(ElementPlus)
app.mount('#app') 