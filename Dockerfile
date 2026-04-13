FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# Create data directory for Railway volume
RUN mkdir -p /app/data

# Set Railway volume path
ENV RAILWAY_VOLUME_MOUNT_PATH=/app/data

EXPOSE 3000

CMD ["npm", "start"]
