#!/bin/bash

# ============================================================
# 360V6 专用精简脚本（LiBwrt 6.12 / immortalwrt 系）
# v4: PassWall2 官方新组织 + deviceid 设备管控 + 三优化
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
  git clone --depth=1 -b $branch --single-branch --filter=blob:none --sparse $repourl
  repodir=$(echo $repourl | awk -F '/' '{print $(NF)}')
  cd $repodir && git sparse-checkout set $@
  mv -f $@ ../package
  cd .. && rm -rf $repodir
}

# 用 codeload 下载 tar 包（比 git clone 更稳，绕开 GitHub clone 限流）
function dl_tar() {
  local org="$1" repo="$2" branch="$3" dest="$4"
  echo "== 下载 ${org}/${repo} (${branch}) 到 ${dest} =="
  mkdir -p package
  wget -qO- "https://codeload.github.com/${org}/${repo}/tar.gz/refs/heads/${branch}" \
    | tar xz -C package/ || { echo "❌ ${repo} 下载失败"; return 1; }
  mv "package/${repo}-${branch}" "package/${dest}" || { echo "❌ ${repo} 解压改名失败"; return 1; }
  echo "✅ ${repo} 已就位 -> package/${dest}"
  return 0
}

# 科学上网插件（PassWall2，官方新组织 Openwrt-Passwall，main 分支）
dl_tar Openwrt-Passwall openwrt-passwall2 main luci-app-passwall2
dl_tar Openwrt-Passwall openwrt-passwall-packages main openwrt-passwall

# 在线用户（查看在线设备 + nlbwmon）
git_sparse_clone main https://github.com/haiibo/packages luci-app-onliner

# 设备管控（deviceid：识别 + 断网/恢复）
dl_tar wyndam luci-app-deviceid main luci-app-deviceid

# Themes（Argon）
git clone --depth=1 https://github.com/jerrykuku/luci-theme-argon package/luci-theme-argon
git clone --depth=1 https://github.com/jerrykuku/luci-app-argon-config package/luci-app-argon-config
[ -f $GITHUB_WORKSPACE/images/bg1.jpg ] && cp -f $GITHUB_WORKSPACE/images/bg1.jpg package/luci-theme-argon/htdocs/luci-static/argon/img/bg1.jpg || true

# ====== 拉取完整性校验：该有的库必须存在，缺失立即失败 ======
echo "######## 源码拉取校验 ########"
pending=0
for d in openwrt-passwall luci-app-passwall2 luci-app-onliner luci-app-deviceid luci-theme-argon luci-app-argon-config; do
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