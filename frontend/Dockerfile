# Use nginx alpine as base image
FROM nginx:alpine

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy frontend static files
COPY . /usr/share/nginx/html

# Remove unnecessary files from the nginx html directory
RUN rm -f /usr/share/nginx/html/Dockerfile \
    /usr/share/nginx/html/nginx.conf \
    /usr/share/nginx/html/README.md

# Create a health check endpoint
RUN echo '<html><body>OK</body></html>' > /usr/share/nginx/html/health

# Expose ports
EXPOSE 80 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]