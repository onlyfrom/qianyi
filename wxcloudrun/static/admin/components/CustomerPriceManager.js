const CustomerPriceManager = {
    template: `
        <el-dialog
            v-model="dialogVisible"
            title="客户商品价格管理"
            width="480px"
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

                <!-- 客户商品价格列表 -->
                <template v-if="form.userId">
                    <!-- 搜索框和新增按钮 -->
                    <el-form-item label="商品管理">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <el-input
                                v-model="searchKeyword"
                                placeholder="输入商品名称或货号搜索"
                                clearable
                                @input="filterPrices"
                                style="flex: 1"
                            >
                                <template #prefix>
                                    <el-icon><Search /></el-icon>
                                </template>
                            </el-input>
                            <el-button type="primary" @click="handleAddProduct">
                                新增商品
                            </el-button>
                        </div>
                    </el-form-item>

                    <!-- 价格列表表格 -->
                    <el-table
                        :data="filteredPrices"
                        style="width: 100%; margin-bottom: 20px"
                        border
                        @row-click="handleEditPrice"
                        :row-style="{ cursor: 'pointer' }"
                    >
                        <el-table-column prop="productName" label="商品名称" width="200" />
                        <el-table-column prop="productId" label="货号" width="120" />
                        <el-table-column prop="price" label="价格" width="120">
                            <template #default="scope">
                                ¥{{ scope.row.price.toFixed(2) }}
                            </template>
                        </el-table-column>
                    </el-table>
                </template>

            
            </el-form>

            <!-- 编辑价格对话框 -->
            <el-dialog
                v-model="editDialogVisible"
                title="修改商品价格"
                width="400px"
                :close-on-click-modal="false"
            >
                <el-form :model="editForm" label-width="80px">
                    <el-form-item label="商品名称">
                        <span>{{ editForm.productName }}</span>
                    </el-form-item>
                    <el-form-item label="货号">
                        <span>{{ editForm.productId }}</span>
                    </el-form-item>
                    <el-form-item label="价格">
                        <el-input-number
                            v-model="editForm.price"
                            :precision="2"
                            :step="0.1"
                            :min="0"
                            style="width: 200px"
                        ></el-input-number>
                    </el-form-item>
                </el-form>
                <template #footer>
                    <span class="dialog-footer">
                        <el-button @click="editDialogVisible = false">取消</el-button>
                        <el-button type="primary" @click="submitEditPrice" :loading="submitting">
                            确定
                        </el-button>
                    </span>
                </template>
            </el-dialog>

            <!-- 新增商品对话框 -->
            <el-dialog
                v-model="addDialogVisible"
                title="新增商品"
                width="400px"
                :close-on-click-modal="false"
            >
                <el-form :model="addForm" label-width="80px">
                    <el-form-item label="选择商品">
                        <el-select
                            v-model="addForm.productId"
                            placeholder="请选择商品（搜索商品）"
                            filterable
                            remote
                            :remote-method="searchProducts"
                            :loading="productSearchLoading"
                            style="width: 100%"
                            @change="handleAddProductSelect"
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
                    <el-form-item label="商品名称">
                        <span>{{ addForm.productName }}</span>
                    </el-form-item>
                    <el-form-item label="价格">
                        <el-input-number
                            v-model="addForm.price"
                            :precision="2"
                            :step="0.1"
                            :min="0"
                            style="width: 200px"
                        ></el-input-number>
                    </el-form-item>
                </el-form>
                <template #footer>
                    <span class="dialog-footer">
                        <el-button @click="addDialogVisible = false">取消</el-button>
                        <el-button type="primary" @click="submitAddProduct" :loading="submitting">
                            确定
                        </el-button>
                    </span>
                </template>
            </el-dialog>

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
            editDialogVisible: false,
            addDialogVisible: false,
            form: {
                userId: null,
                productId: null,
                price: 0
            },
            editForm: {
                productName: '',
                productId: null,
                price: 0
            },
            addForm: {
                productId: null,
                productName: '',
                price: 0
            },
            userSearchResults: [],
            productSearchResults: [],
            userProductPrices: [], // 存储所有价格数据
            filteredPrices: [], // 存储筛选后的价格数据
            searchKeyword: '', // 搜索关键词
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
            if (!userId) {
                this.userProductPrices = [];
                this.filteredPrices = [];
                this.searchKeyword = '';
                return;
            }
            
            try {
                // 获取该用户的所有商品价格
                const response = await axios.get('/user-product-prices/all', {
                    params: { customer_id: userId }
                });
                
                if (response.data.code === 0) {
                    this.userProductPrices = response.data.prices || [];
                    this.filteredPrices = [...this.userProductPrices]; // 初始化筛选后的数据
                } else {
                    console.error('获取用户商品价格失败:', response.data.message);
                    ElementPlus.ElMessage.error(response.data.message || '获取用户商品价格失败');
                }

                // 如果已选择了商品，获取该用户对应商品的价格
                if (this.form.productId) {
                    await this.fetchUserProductPrice();
                }
            } catch (error) {
                console.error('获取用户商品价格失败:', error);
                ElementPlus.ElMessage.error('获取用户商品价格失败');
            }
        },

        // 筛选价格列表
        filterPrices() {
            if (!this.searchKeyword) {
                this.filteredPrices = [...this.userProductPrices];
                return;
            }
            
            const keyword = this.searchKeyword.toLowerCase();
            this.filteredPrices = this.userProductPrices.filter(item => 
                item.productName.toLowerCase().includes(keyword) || 
                item.productId.toString().includes(keyword)
            );
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

        // 处理编辑价格
        handleEditPrice(row) {
            this.editForm = {
                productName: row.productName,
                productId: row.productId,
                price: row.price
            };
            this.editDialogVisible = true;
        },

        // 提交编辑价格
        async submitEditPrice() {
            if (!this.form.userId || !this.editForm.productId) {
                ElementPlus.ElMessage.warning('缺少必要参数');
                return;
            }

            try {
                this.submitting = true;
                const response = await axios.post('/user-product-prices', {
                    user_id: this.form.userId,
                    product_id: this.editForm.productId,
                    price: this.editForm.price
                });

                if (response.data.code === 0) {
                    ElementPlus.ElMessage.success('价格修改成功');
                    this.editDialogVisible = false;
                    // 更新列表中的价格
                    const index = this.userProductPrices.findIndex(
                        item => item.productId === this.editForm.productId
                    );
                    if (index !== -1) {
                        this.userProductPrices[index].price = this.editForm.price;
                        this.filterPrices(); // 重新筛选
                    }
                } else {
                    ElementPlus.ElMessage.error(response.data.message || '价格修改失败');
                }
            } catch (error) {
                console.error('修改价格失败:', error);
                ElementPlus.ElMessage.error('修改价格失败');
            } finally {
                this.submitting = false;
            }
        },

        // 处理新增商品
        handleAddProduct() {
            this.addForm = {
                productId: null,
                productName: '',
                price: 0
            };
            this.productSearchResults = [];
            this.addDialogVisible = true;
        },

        // 处理新增商品选择
        handleAddProductSelect(productId) {
            const product = this.productSearchResults.find(p => p.id === productId);
            if (product) {
                this.addForm.productName = product.name;
            }
        },

        // 提交新增商品
        async submitAddProduct() {
            if (!this.form.userId || !this.addForm.productId) {
                ElementPlus.ElMessage.warning('请选择商品');
                return;
            }

            try {
                this.submitting = true;
                const response = await axios.post('/user-product-prices', {
                    user_id: this.form.userId,
                    product_id: this.addForm.productId,
                    price: this.addForm.price
                });

                if (response.data.code === 0) {
                    ElementPlus.ElMessage.success('商品添加成功');
                    this.addDialogVisible = false;
                    // 重新获取价格列表
                    await this.handleUserSelect(this.form.userId);
                } else {
                    ElementPlus.ElMessage.error(response.data.message || '商品添加失败');
                }
            } catch (error) {
                console.error('添加商品失败:', error);
                ElementPlus.ElMessage.error('添加商品失败');
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
            this.editForm = {
                productName: '',
                productId: null,
                price: 0
            };
            this.addForm = {
                productId: null,
                productName: '',
                price: 0
            };
            this.userSearchResults = [];
            this.productSearchResults = [];
            this.userProductPrices = [];
            this.filteredPrices = [];
            this.searchKeyword = '';
            this.editDialogVisible = false;
            this.addDialogVisible = false;
        }
    }
};

// 注册组件
window.CustomerPriceManager = CustomerPriceManager; 