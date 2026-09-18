# Pod Cloud Web 前端镜像:多阶段构建(node 构建 → nginx 托管)
# 构建: docker build -f deploy/Dockerfile -t podcloud-web:<tag> .
FROM node:20-alpine AS build

# 本次构建的标识（镜像 tag）→ 前端构建时经 VITE_BUILD_TAG 打进产物，
# 界面侧栏显示"构建 <tag>"，与后端 /auth/config 返回的 build 对照。
ARG BUILD_TAG=dev
ENV VITE_BUILD_TAG=$BUILD_TAG

# 本次构建来自哪个 commit（与后端 /auth/config 的 build_commit 对照）。
# tag 是每镜像独立的内容指纹，不能用来判断"前后端是不是同一次发布"。
ARG BUILD_COMMIT=
ENV VITE_BUILD_COMMIT=$BUILD_COMMIT

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html

# SPA 路由回退 + 后端 API 反代(upstream 地址由环境变量注入)
COPY deploy/nginx.conf.template /etc/nginx/templates/default.conf.template
RUN chmod 644 /etc/nginx/templates/default.conf.template
ENV PODCLOUD_SERVER_UPSTREAM=podcloud-server:8000

EXPOSE 80
