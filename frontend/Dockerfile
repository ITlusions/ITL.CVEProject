FROM node:24-slim AS build
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /src/dist /usr/share/nginx/html
ENV BACKEND_URL=http://cve-backend:80
EXPOSE 8080
