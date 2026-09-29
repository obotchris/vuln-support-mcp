FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY index.js ./

ENV PORT=8000
ENV MCP_PATH=/mcp
EXPOSE 8000

CMD ["node", "index.js"]
