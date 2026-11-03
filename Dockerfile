FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run typecheck && npm test && npm run build
RUN npm prune --omit=dev --ignore-scripts

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:b8cec4b2f2126ff7bd034ec9ac207ffb3272667dfdc48376e3b035d3270549ba AS runtime
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4310
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/dist/src ./dist/src
COPY --from=build /app/dist/web ./dist/web
USER 65532:65532
EXPOSE 4310
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:4310/health',{headers:{host:new URL(process.env.BASE_URL || 'http://127.0.0.1:4310').host}}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["dist/src/main.js"]
