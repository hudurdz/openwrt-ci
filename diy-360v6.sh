#!/bin/bash

# ============================================================
# 360V6 专用精简脚本（LiBwrt 6.12 / immortalwrt 系）
# v3 代理版：clone 走 gh-proxy 代理 + 拉取后完整性校验（缺失即红）
# ============================================================

# 修改默认IP 为 10.0.7.1
sed -i 's/192.168.1.1/10.0.7.1/g' package/base-files/files/bin/config_generate

# 移除要替换的多余 feeds 包
rm -rf feeds/packages/net/mosdns
rm -rf feeds/packages/net/msd_lite
rm -rf feeds/packages/net/smartdns
rm -rf feeds/luci/themes/luci-theme-argon
rm -rf feeds/luci/applications/luci-app-mosdns
rm -rf feeds/luci/applications/luci-app-netdata

# Git稀疏克隆，只克隆指定目录到本地
function git_sparse_clone() {
  branch="$1" repourl="$2" && shift 2
  [ -n "$PROXY_PREFIX" ] && repourl="${PROXY_PREFIX}${repourl}"
  git clone --depth=1 -b $branch --single-branch --filter=blob:none --sparse $repourl
  repodir=$(echo $repourl | awk -F '/' '{print $(NF)}')
  cd $repodir && git sparse-checkout set $@
  mv -f $@ ../package
  cd .. && rm -rf $repodir
}

# 代理前缀（gh-proxy 镜像，绕过 GitHub 对 Actions 的限流）
PROXY_PREFIX="https://gh-proxy.com/"

# 科学上网插件（仅 PassWall2，走代理）
git clone --depth=1 ${PROXY_PREFIX}https://github.com/xiaorouji/openwrt-passwall-packages package/openwrt-passwall
git clone --depth=1 ${PROXY_PREFIX}https://github.com/xiaorouji/openwrt-passwall2 package/luci-app-passwall2

# 在线用户（查看在线设备 + nlbwmon，走代理）
git_sparse_clone main https://github.com/haiibo/packages luci-app-onliner

# Themes（Argon，走代理）
git clone --depth=1 ${PROXY_PREFIX}https://github.com/jerrykuku/luci-theme-argon package/luci-theme-argon
git clone --depth=1 ${PROXY_PREFIX}https://github.com/jerrykuku/luci-app-argon-config package/luci-app-argon-config
[ -f $GITHUB_WORKSPACE/images/bg1.jpg ] && cp -f $GITHUB_WORKSPACE/images/bg1.jpg package/luci-theme-argon/htdocs/luci-static/argon/img/bg1.jpg || true

# ====== 拉取完整性校验：该有的库必须存在，缺失立即失败 ======
echo "######## 源码拉取校验 ########"
pending=0
for d in openwrt-passwall luci-app-passwall2 luci-app-onliner luci-theme-argon luci-app-argon-config; do
  if [ -d "package/$d" ]; then
    echo "✅ $d 已就位"
  else
    echo "❌ $d 缺失！"
    pending=1
  fi
done
if [ $pending -eq 1 ]; then
  echo "ERROR: 关键源码拉取失败，中止编译"
  exit 1
fi

# 修改版本为编译日期
date_version=$(date +"%y.%m.%d")
if [ -f package/lean/default-settings/files/zzz-default-settings ]; then
  orig_version=$(grep DISTRIB_REVISION= package/lean/default-settings/files/zzz-default-settings | awk -F "'" '{print $2}')
  sed -i "s/${orig_version}/R${date_version}/g" package/lean/default-settings/files/zzz-default-settings
fi

# 修复 hostapd 报错
cp -f $GITHUB_WORKSPACE/scripts/011-fix-mbo-modules-build.patch package/network/services/hostapd/patches/011-fix-mbo-modules-build.patch

# 修复 armv8 设备 xfsprogs 报错
sed -i 's/TARGET_CFLAGS.*/TARGET_CFLAGS += -DHAVE_MAP_SYNC -D_LARGEFILE64_SOURCE/g' feeds/packages/utils/xfsprogs/Makefile

# 修改 Makefile
find package/*/ -maxdepth 2 -path "*/Makefile" | xargs -i sed -i 's/..\/..\/luci.mk/$(TOPDIR)\/feeds\/luci\/luci.mk/g' {}
find package/*/ -maxdepth 2 -path "*/Makefile" | xargs -i sed -i 's/..\/..\/lang\/golang\/golang-package.mk/$(TOPDIR)\/feeds\/packages\/lang\/golang\/golang-package.mk/g' {}
find package/*/ -maxdepth 2 -path "*/Makefile" | xargs -i sed -i 's/PKG_SOURCE_URL:=@GHREPO/PKG_SOURCE_URL:=https:\/\/github.com/g' {}
find package/*/ -maxdepth 2 -path "*/Makefile" | xargs -i sed -i 's/PKG_SOURCE_URL:=@GHCODELOAD/PKG_SOURCE_URL:=https:\/\/codeload.github.com/g' {}

# 取消主题默认设置
find package/luci-theme-*/* -type f -name '*luci-theme-*' -print -exec sed -i '/set luci.main.mediaurlbase/d' {} \;

./scripts/feeds update -a
./scripts/feeds install -a
