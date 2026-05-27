FROM node:22-slim
WORKDIR /app
COPY package.json ./
COPY public ./public
COPY server ./server
EXPOSE 8080
CMD ["node", "server/index.mjs"]
