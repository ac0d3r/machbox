import { createRouter, createWebHashHistory } from 'vue-router'
import ReportList from './views/ReportList.vue'
import ReportDetail from './views/ReportDetail.vue'

const routes = [
  { path: '/', component: ReportList },
  { path: '/report/:id', component: ReportDetail },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
