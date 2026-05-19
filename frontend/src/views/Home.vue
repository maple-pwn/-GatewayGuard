<template>
  <div class="home-page">
    <section class="hero">
      <div class="hero__backdrop" />
      <div class="hero__veil" />

      <div class="hero__content">
        <div class="hero__eyebrow">Intelligent Vehicle Security Platform</div>
        <h1>GatewayGuard</h1>
        <p>
          面向智能网联汽车场景的统一安全监测与分析平台，
          集成车载流量采集、异常检测、事件研判与 AI 辅助分析能力，
          帮助研究人员和分析员更高效地识别攻击行为、追踪异常来源并完成安全态势评估。
        </p>
        <div class="hero__actions">
          <button type="button" class="hero__cta hero__cta--primary" @click="enterConsole">
            Enter Official Console
          </button>
          <button type="button" class="hero__cta" @click="enterAbout">
            About Our GatewayGuard
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'

const router = useRouter()

function enterConsole() {
  window.localStorage.setItem('gg-ui-mode', 'immersive')
  router.push('/immersive/console')
}

function enterAbout() {
  window.localStorage.setItem('gg-ui-mode', 'immersive')
  router.push('/immersive/about')
}
</script>

<style scoped>
.home-page {
  position: relative;
  min-height: 100vh;
  overflow: hidden;
  background: #02070d;
}

.hero {
  position: relative;
  display: grid;
  place-items: center;
  min-height: 100vh;
}

.hero__backdrop {
  position: absolute;
  inset: 0;
  background-image: url('../assets/home-hero.png');
  background-size: cover;
  background-position: center;
  transform: scale(1.08);
  animation: heroPan 12s ease-out forwards;
}

.hero__veil {
  position: absolute;
  inset: 0;
  background:
    linear-gradient(180deg, rgba(8, 10, 16, 0.02) 42%, rgba(0, 0, 0, 0.82) 100%),
    radial-gradient(700px 280px at 50% 36%, rgba(13, 36, 58, 0.18), transparent 70%);
}

.hero__content {
  position: relative;
  z-index: 2;
  display: grid;
  justify-items: center;
  justify-content: center;
  align-content: center;
  gap: 16px;
  width: min(960px, calc(100% - 48px));
  margin: 0 auto;
  padding: 72px 24px 0;
  text-align: center;
}

.hero__eyebrow {
  color: rgba(235, 241, 255, 0.92);
  font-size: 12px;
  letter-spacing: 0.34em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
  animation: riseIn 1s ease-out forwards;
}

.hero h1 {
  margin: 0;
  font-size: clamp(60px, 10.8vw, 138px);
  line-height: 0.92;
  color: #fff;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding-left: 0.05em;
  font-family: var(--gg-font-display);
  text-shadow: 0 14px 48px rgba(0, 0, 0, 0.28);
  animation: riseIn 1.2s ease-out forwards;
}

.hero p {
  margin: 0;
  max-width: 740px;
  color: rgba(242, 246, 255, 0.8);
  line-height: 1.95;
  font-size: 15px;
  animation: riseIn 1.35s ease-out forwards;
}

.hero__actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  align-items: center;
  gap: 14px;
  width: 100%;
}

.hero__cta {
  min-height: 52px;
  padding: 0 28px;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.28);
  color: rgba(247, 250, 255, 0.92);
  background: rgba(255, 255, 255, 0.04);
  font-size: 15px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  font-family: var(--gg-font-ui);
  font-weight: 700;
  cursor: pointer;
  transition: transform 0.2s ease, background 0.2s ease, color 0.2s ease;
  animation: riseIn 1.5s ease-out forwards;
}

.hero__cta--primary {
  border-color: rgba(151, 175, 255, 0.34);
  background: rgba(99, 132, 255, 0.22);
}

.hero__cta:hover {
  transform: translateY(-2px);
  background: rgba(255, 255, 255, 0.86);
  color: #20323d;
}

@keyframes heroPan {
  from {
    background-position: 50% 0%;
  }
  to {
    background-position: 50% 14%;
  }
}

@keyframes riseIn {
  from {
    transform: translateY(120px);
    opacity: 0;
  }
  to {
    transform: translateY(0);
    opacity: 1;
  }
}

@media (max-width: 820px) {
  .hero__content {
    width: min(100%, calc(100% - 28px));
    padding: 90px 12px 0;
  }

  .hero h1 {
    font-size: clamp(46px, 16vw, 78px);
    letter-spacing: 0.035em;
    padding-left: 0.035em;
  }

  .hero p {
    font-size: 14px;
  }

  .hero__actions {
    width: 100%;
    flex-direction: column;
  }
}
</style>
