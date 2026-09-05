FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=5173 \
    PUBLIC_API_URL=http://localhost:8000
RUN addgroup -S socwerk && adduser -S socwerk -G socwerk
WORKDIR /app
COPY --from=build --chown=socwerk:socwerk /app/build ./build
COPY --from=build --chown=socwerk:socwerk /app/package.json ./package.json
COPY --from=build --chown=socwerk:socwerk /app/node_modules ./node_modules
USER socwerk
EXPOSE 5173
CMD ["node", "build"]
