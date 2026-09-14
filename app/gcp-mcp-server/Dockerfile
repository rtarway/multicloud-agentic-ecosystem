FROM node:22-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production || npm install --only=production

COPY . .

EXPOSE 8081

ENV NODE_ENV=production
ENV PORT=8081

CMD ["node", "src/index.js"]
