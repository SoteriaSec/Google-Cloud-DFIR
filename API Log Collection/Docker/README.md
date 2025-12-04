
# GCP Log Collector Docker Container
Docker container with Python script that collects logs from Google Cloud via API.

**Credit:**  
The Python script inside this container was authored by [Josh Lemon](https://github.com/joshlemon), for [SoteriaSec](https://github.com/SoteriaSec).

---

## Prerequisites

1. **Install Docker Desktop**  
   Download and install Docker Desktop for your platform:  
   https://www.docker.com/products/docker-desktop

2. **Verify Docker**  
   ```bash docker --version```

## Pull Public Container from Docker Hub

_You only need to do this OR a Clone from GitHub, you don't need to do both._

1.  **Pull Container from Docker Hub**
    ```
    docker pull soteriasec/gcp_log_collector
    ```

## Clone Container from GitHub

_You only need to do this OR a Pull from Docker Hub, you don't need to do both._

1.  **Get the Repository**
    
    ```
    git clone https://github.com/SoteriaSec/Google-Cloud-DFIR.git
    cd cd API\ Log\ Collection/Docker/ 
    ```

2. **Build the Docker Image**
   
    ``` docker build -t gcp-log-collector . ```


## Run the Container

1. **First Time Run of the Container**
   
   Authenticates and lists projects.
   
   ``` 
   docker run --rm -it \
    -v "$(pwd)/gcp-log-config":/config \
    gcp-log-collector \
    list-projects
   ```

   - The container reads `/config/client_secret.json`.
   - Runs the OAuth flow; a browser opens or a URL is printed.
   - After approval, `token.json` is written to `/config` (on the host).
   - Projects are listed.

2. **List Buckets**

   ```
   docker run --rm -it \
     -v "$(pwd)/gcp-log-config":/config \
     gcp-log-collector \
     list-buckets \
     --project-id my-ir-project
   ```

   With views:
   ```
   docker run --rm -it \
     -v "$(pwd)/gcp-log-config":/config \
     gcp-log-collector \
     list-buckets \
     --project-id my-ir-project \
     --show-views
   ```

3. **Collect logs for a project into a single file**

   Here we’ll also mount a `/data` directory so the exported logs end up on the host cleanly.
   ```
   mkdir -p logs-out
   ```

   Then:
   ```
   docker run --rm -it \
     -v "$(pwd)/gcp-log-config":/config \
     -v "$(pwd)/logs-out":/data \
     gcp-log-collector \
     collect-logs \
     --project-id my-ir-project \
     --start-time 2025-11-01T00:00:00Z \
     --end-time   2025-11-02T00:00:00Z \
     --output /data/my_ir_logs.jsonl
   ```

   Results will be in the `logs-out/my_ir_logs.jsonl` file on the host.



## To Do
- Provide a Windows-specific usage example
