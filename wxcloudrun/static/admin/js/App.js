export default {
    template: `
        <div v-if="!isLoggedIn" class="login-container">
            <el-card class="login-card">
                <h2>登录杭州仟艺服饰后台管理系统</h2>
                <el-form>
                    <el-form-item>
                        <el-input v-model="loginForm.username" placeholder="用户名"></el-input>
                    </el-form-item>
                    <el-form-item>
                        <el-input v-model="loginForm.password" type="password" placeholder="密码"></el-input>
                    </el-form-item>
                    <el-button type="primary" @click="handleLogin" style="width: 100%">登录</el-button>
                </el-form>
            </el-card>
        </div>
        <div v-else>
            <el-container>
                <el-header>
                    <div class="header-content">
                        <h2>杭州仟艺服饰后台管理系统</h2>
                        <el-button type="danger" @click="handleLogout">退出登录</el-button>
                    </div>
                </el-header>
                <el-main>
                    <div class="toolbar">
                        <el-button type="primary" @click="showAddDialog">新增商品</el-button>
                    </div>
                    
                    <el-table :data="products" style="width: 100%" :max-height="tableMaxHeight">
                        <el-table-column prop="id" label="ID" width="180"></el-table-column>
                        <el-table-column prop="name" label="商品名称"></el-table-column>
                        <el-table-column prop="price" label="价格"></el-table-column>
                        <el-table-column prop="type" label="类型"></el-table-column>
                        <el-table-column label="操作" width="200">
                            <template #default="scope">
                                <el-button size="small" @click="handleEdit(scope.row)">编辑</el-button>
                                <el-button size="small" type="danger" @click="handleDelete(scope.row)">删除</el-button>
                            </template>
                        </el-table-column>
                    </el-table>

                    <!-- 新增/编辑商品对话框 -->
                    <el-dialog :title="dialogTitle" v-model="dialogVisible" width="50%">
                        <el-form :model="productForm" label-width="100px">
                            <el-form-item label="商品名称">
                                <el-input v-model="productForm.name"></el-input>
                            </el-form-item>
                            <el-form-item label="商品描述">
                                <el-input type="textarea" v-model="productForm.description"></el-input>
                            </el-form-item>
                            <el-form-item label="价格">
                                <el-input-number v-model="productForm.price" :precision="2"></el-input-number>
                            </el-form-item>
                            <el-form-item label="商品类型">
                                <el-select v-model="productForm.type">
                                    <el-option label="类型1" :value="0"></el-option>
                                    <el-option label="类型2" :value="1"></el-option>
                                    <el-option label="类型3" :value="2"></el-option>
                                </el-select>
                            </el-form-item>
                            <el-form-item label="商品图片">
                                <el-upload
                                    action="/upload"
                                    list-type="picture-card"
                                    :on-success="handleUploadSuccess"
                                    :on-remove="handleRemove">
                                    <el-icon><Plus /></el-icon>
                                </el-upload>
                            </el-form-item>
                        </el-form>
                        <template #footer>
                            <el-button @click="dialogVisible = false">取消</el-button>
                            <el-button type="primary" @click="handleSave">确定</el-button>
                        </template>
                    </el-dialog>
                </el-main>
            </el-container>
        </div>
    `,
    data() {
        return {
            isLoggedIn: false,
            loginForm: {
                username: '',
                password: ''
            },
            products: [],
            dialogVisible: false,
            dialogTitle: '新增商品',
            productForm: {
                id: '',
                name: '',
                description: '',
                price: 0,
                type: 0,
                images: []
            },
            isEdit: false,
            windowHeight: window.innerHeight,
        }
    },
    computed: {
        tableMaxHeight() {
            // 减去头部高度(60px)、工具栏高度(60px)和底部边距(20px)
            return this.windowHeight - 140
        }
    },
    created() {
        // 检查是否已登录
        const token = localStorage.getItem('admin_token')
        if (token) {
            this.isLoggedIn = true
            this.fetchProducts()
        }
    },
    mounted() {
        window.addEventListener('resize', this.handleResize)
    },
    beforeUnmount() {
        window.removeEventListener('resize', this.handleResize)
    },
    methods: {
        handleResize() {
            this.windowHeight = window.innerHeight
        },
        async handleLogin() {
            try {
                const response = await axios.post('/login', this.loginForm)
                if (response.data.token) {
                    localStorage.setItem('admin_token', response.data.token)
                    this.isLoggedIn = true
                    this.fetchProducts()
                }
            } catch (error) {
                ElMessage.error('登录失败：' + error.response?.data?.error || '未知错误')
            }
        },
        handleLogout() {
            localStorage.removeItem('admin_token')
            this.isLoggedIn = false
        },
        async fetchProducts() {
            try {
                const response = await axios.get('/products')
                this.products = response.data.products
            } catch (error) {
                ElMessage.error('获取商品列表失败')
            }
        },
        showAddDialog() {
            this.isEdit = false
            this.dialogTitle = '新增商品'
            this.productForm = {
                name: '',
                description: '',
                price: 0,
                type: 0,
                images: []
            }
            this.dialogVisible = true
        },
        handleEdit(row) {
            this.isEdit = true
            this.dialogTitle = '编辑商品'
            this.productForm = { ...row }
            this.dialogVisible = true
        },
        async handleDelete(row) {
            try {
                await ElMessageBox.confirm('确定要删除该商品吗？', '提示', {
                    type: 'warning'
                })
                await axios.delete(`/products/${row.id}`, {
                    headers: { Authorization: localStorage.getItem('admin_token') }
                })
                ElMessage.success('删除成功')
                this.fetchProducts()
            } catch (error) {
                if (error !== 'cancel') {
                    ElMessage.error('删除失败：' + error.response?.data?.error || '未知错误')
                }
            }
        },
        async handleSave() {
            try {
                const headers = { Authorization: localStorage.getItem('admin_token') }
                if (this.isEdit) {
                    await axios.put(`/products/${this.productForm.id}`, this.productForm, { headers })
                } else {
                    await axios.post('/products', this.productForm, { headers })
                }
                ElMessage.success(this.isEdit ? '更新成功' : '添加成功')
                this.dialogVisible = false
                this.fetchProducts()
            } catch (error) {
                ElMessage.error((this.isEdit ? '更新' : '添加') + '失败：' + error.response?.data?.error || '未知错误')
            }
        },
        handleUploadSuccess(response, file) {
            this.productForm.images.push(response.url)
        },
        handleRemove(file) {
            const index = this.productForm.images.indexOf(file.url)
            if (index > -1) {
                this.productForm.images.splice(index, 1)
            }
        }
    }
} 