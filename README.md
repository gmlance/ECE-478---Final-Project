1) Navigate to your project directory.
2) Build and start the Docker containers:
  docker-compose up --build
3) Access the victim container:
  docker exec -it <victim_container_id> /bin/bash
4) From within the victim container, perform DNS queries:
  nslookup example.com
