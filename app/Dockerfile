# syntax=docker/dockerfile:1
FROM node:lts-alpine as builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci
COPY src tsconfig.json ./
RUN npm run build && sleep 30s
# intentional sleep here to delay the build process

FROM node:lts-alpine as runtime

WORKDIR /app

COPY --from=builder /app/bin ./bin
COPY . .

ENTRYPOINT [ "npm", "run", "start" ]
