const CustomerPriceManager = {
    template: `
        <el-dialog
            v-model="dialogVisible"
            title="客户商品价格管理"
            width="600px"
            :close-on-click-modal="false"
            @closed="handleClose"
        >
            <!-- 客户选择 -->
            <el-form :model="form" label-width="100px">
                <el-form-item label="选择客户">
                    <el-select
                        v-model="form.userId"
                        placeholder="请选择客户（搜索客户）"
                        filterable
                        remote
                        :remote-method="searchUsers"
                        :loading="userSearchLoading"
                        style="width: 100%"
                        @change="handleUserSelect"
                    >
                        <el-option
                            v-for="user in userSearchResults"
                            :key="user.id"
                            :label="user.nickname || user.username"
                            :value="user.id"
                        >
                            <span>{{ user.nickname || user.username }}</span>
                            <span style="float: right; color: #8492a6; font-size: 13px">
                                {{ user.phone || '无电话' }}
                            </span>
                        </el-option>
                    </el-select>
                </el-form-item>

                <!-- 商品选择 -->
                <el-form-item label="选择商品">
                    <el-select
                        v-model="form.productId"
                        placeholder="请选择商品（搜索商品）"
                        filterable
                        remote
                        :remote-method="searchProducts"
                        :loading="productSearchLoading"
                        style="width: 100%"
                        @change="handleProductSelect"
                    >
                        <el-option
                            v-for="product in productSearchResults"
                            :key="product.id"
                            :label="product.name"
                            :value="product.id"
                        >
                            <span>{{ product.name }}</span>
                            <span style="float: right; color: #8492a6; font-size: 13px">
                                款号: {{ product.id }}
                            </span>
                        </el-option>
                    </el-select>
                </el-form-item>

                <!-- 价格设置 -->
                <el-form-item label="商品价格">
                    <el-input-number
                        v-model="form.price"
                        :precision="2"
                        :step="0.1"
                        :min="0"
                        style="width: 200px"
                    ></el-input-number>
                </el-form-item>
            </el-form>

            <template #footer>
                <span class="dialog-footer">
                    <el-button @click="dialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="submitPrice" :loading="submitting">
                        确定
                    </el-button>
                </span>
            </template>
        </el-dialog>
    `,

    props: {
        visible: {
            type: Boolean,
            default: false
        }
    },

    data() {
        return {
            dialogVisible: false,
            form: {
                userId: null,
                productId: null,
                price: 0
            },
            userSearchResults: [],
            productSearchResults: [],
            userSearchLoading: false,
            productSearchLoading: false,
            submitting: false
        }
    },

    watch: {
        visible(val) {
            this.dialogVisible = val;
        },
        dialogVisible(val) {
            this.$emit('update:visible', val);
        }
    },

    methods: {
        // 搜索用户
        async searchUsers(query) {
            if (query.length < 1) {
                this.userSearchResults = [];
                return;
            }
            
            try {
                this.userSearchLoading = true;
                const response = await axios.get('/users/search', {
                    params: { keyword: query }
                });
                
                if (response.status === 200) {
                    this.userSearchResults = response.data.users;
                }
            } catch (error) {
                console.error('搜索用户失败:', error);
                ElementPlus.ElMessage.error('搜索用户失败');
            } finally {
                this.userSearchLoading = false;
            }
        },

        // 搜索商品
        async searchProducts(query) {
            if (query.length < 1) {
                this.productSearchResults = [];
                return;
            }
            
            try {
                this.productSearchLoading = true;
                const response = await axios.get('/products', {
                    params: {
                        keyword: query,
                        page: 1,
                        page_size: 10
                    }
                });
                
                if (response.status === 200) {
                    this.productSearchResults = response.data.products;
                }
            } catch (error) {
                console.error('搜索商品失败:', error);
                ElementPlus.ElMessage.error('搜索商品失败');
            } finally {
                this.productSearchLoading = false;
            }
        },

        // 处理用户选择
        async handleUserSelect(userId) {
            if (!userId) return;
            
            try {
                // 如果已选择了商品，获取该用户对应商品的价格
                if (this.form.productId) {
                    await this.fetchUserProductPrice();
                }
            } catch (error) {
                console.error('获取用户商品价格失败:', error);
                ElementPlus.ElMessage.error('获取用户商品价格失败');
            }
        },

        // 处理商品选择
        async handleProductSelect(productId) {
            if (!productId) return;
            
            try {
                // 如果已选择了用户，获取该用户对应商品的价格
                if (this.form.userId) {
                    await this.fetchUserProductPrice();
                }
            } catch (error) {
                console.error('获取用户商品价格失败:', error);
                ElementPlus.ElMessage.error('获取用户商品价格失败');
            }
        },

        // 获取用户商品价格
        async fetchUserProductPrice() {
            try {
                const response = await axios.get('/user-product-prices', {
                    params: {
                        user_id: this.form.userId,
                        product_id: this.form.productId
                    }
                });
                
                if (response.status === 200) {
                    this.form.price = response.data.price || 0;
                }
            } catch (error) {
                console.error('获取价格失败:', error);
                ElementPlus.ElMessage.error('获取价格失败');
            }
        },

        // 提交价格
        async submitPrice() {
            if (!this.form.userId || !this.form.productId) {
                ElementPlus.ElMessage.warning('请选择客户和商品');
                return;
            }

            try {
                this.submitting = true;
                const response = await axios.post('/user-product-prices', {
                    user_id: this.form.userId,
                    product_id: this.form.productId,
                    price: this.form.price
                });

                if (response.status === 200) {
                    ElementPlus.ElMessage.success('价格设置成功');
                    this.dialogVisible = false;
                }
            } catch (error) {
                console.error('设置价格失败:', error);
                ElementPlus.ElMessage.error('设置价格失败');
            } finally {
                this.submitting = false;
            }
        },

        // 关闭对话框时重置表单
        handleClose() {
            this.form = {
                userId: null,
                productId: null,
                price: 0
            };
            this.userSearchResults = [];
            this.productSearchResults = [];
        }
    }
};

// 注册组件
window.CustomerPriceManager = CustomerPriceManager; 