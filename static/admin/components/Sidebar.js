export default {
    template: `
        <el-aside width="200px">
            <el-menu 
                :default-active="activeMenu" 
                background-color="#545c64" 
                text-color="#fff" 
                active-text-color="#ffd04b"
                @select="handleSelect"
            >
                <el-menu-item index="products">
                    <el-icon><Document /></el-icon>
                    <span>商品管理</span>
                </el-menu-item>

                <el-menu-item index="purchase">
                    <el-icon><ShoppingCart /></el-icon>
                    <span>采购管理</span>
                </el-menu-item>

                <el-menu-item index="stats">
                    <el-icon><TrendCharts /></el-icon>
                    <span>数据统计</span>
                </el-menu-item>

                <el-menu-item index="settings">
                    <el-icon><Setting /></el-icon>
                    <span>系统设置</span>
                </el-menu-item>
            </el-menu>
        </el-aside>
    `,
    props: {
        activeMenu: {
            type: String,
            default: 'products'
        }
    },
    methods: {
        handleSelect(key) {
            this.$emit('menu-select', key);
        }
    }
} 