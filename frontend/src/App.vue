<template>
  <el-container style="height: 100vh">
    <el-header style="background: #1a1a2e; padding: 0">
      <div style="display: flex; align-items: center; height: 60px; padding: 0 20px">
        <h2 style="color: #e94560; margin: 0; font-size: 18px">
          GatewayGuard
        </h2>
        <span style="color: #aaa; margin-left: 12px; font-size: 13px">
          智能网关网络分析平台
        </span>
        <el-menu
          :default-active="$route.path"
          mode="horizontal"
          router
          background-color="#1a1a2e"
          text-color="#ccc"
          active-text-color="#e94560"
          style="margin-left: 40px; border: none"
        >
          <el-menu-item index="/">流量监控</el-menu-item>
          <el-menu-item index="/anomaly">告警中心</el-menu-item>
          <el-menu-item index="/chat">AI 分析</el-menu-item>
        </el-menu>
      </div>
    </el-header>
    <el-main style="background: #f0f2f5; padding: 20px">
      <router-view />
    </el-main>
  </el-container>
</template>
