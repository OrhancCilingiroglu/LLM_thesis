from pathlib import Path
import traceback
import requests
import time
from requests.exceptions import RequestException
import docker
from docker.errors import DockerException, NotFound


class DockerManager:
    def __init__(self, workdir: str, tag: str, port: int):
        self.workdir = str(Path(workdir).resolve())
        self.tag = f"app_{tag}"
        self.port = port
        self.name = f"app_{tag}"

        try:
            # If it fails, uninstall any docker-py package, pip install docker
            self.client = docker.from_env()
        except DockerException as e:
            print(f"FAIL: Docker client initialization failed: {e}")
            self.client = None

    def build_image(self) -> bool:
        """Build Docker image from workdir with given tag."""
        if not self.client:
            print("FAIL: Docker client not initialized")
            return False

        try:
            print(f"\nBUILD Docker image: {self.tag}")
            image, logs = self.client.images.build(
                path=self.workdir,
                tag=self.tag,
                rm=True,
            )
            # logs: iterable of dicts with "stream" usually
            for chunk in logs:
                if isinstance(chunk, dict) and "stream" in chunk:
                    line = chunk["stream"].strip()
                    if line:
                        print(line)
            print(f"SUCCESS: Image '{self.tag}' built.")
            return True

        except Exception:
            print("FAIL: Docker build failed:")
            traceback.print_exc()
            return False


#! Needs testing
    def run_container(self, container_port: int | None = None):
        """Run container from built image, bind workdir to /app and expose port."""
        if not self.client:
            print("FAIL: Docker client not initialized")
            return None

        try:
            print(f"\nRUN Docker container from image: {self.tag}")
            c_port = container_port or self.port
            ports = {f"{c_port}/tcp": self.port}

            container = self.client.containers.run(
                image=self.tag,
                name=self.tag,
                ports=ports,
                volumes={self.workdir: {"bind": "/app", "mode": "rw"}},
                detach=True,
            )
            print(f"INFO: Container '{self.tag}' started on port {self.port}")

            # --- Wait and check if container is running ---
            time.sleep(1.5)  # give app time to boot
            container.reload()
            if container.status != "running":
                logs = container.logs(tail=2000).decode("utf-8", errors="replace")
                print(f"FAIL: Container exited early. status={container.status}\n---logs---\n{logs}\n----------")
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                return None
            
            def _http_ok(path: str) -> bool:
                url = f"http://127.0.0.1:{self.port}{path}"
                try:
                    r = requests.get(url, timeout=1.5, allow_redirects=False)
                    # Any HTTP status means server is up (even 404)
                    return True
                except RequestException:
                    return False
            
            ok = False
            for _ in range(6):  # retry ~6s
                if _http_ok("/health") or _http_ok("/"):
                    ok = True
                    break
                time.sleep(1.0)

            if not ok:
                logs = container.logs(tail=2000).decode("utf-8", errors="replace")
                print(f"FAIL: HTTP not responding on {self.port}.\n---logs---\n{logs}\n----------")
                # cleanup
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                return None
            
            print(f"SUCCESS: App is responding on port {self.port}")
            return container

        except Exception:
            print("FAIL: Unexpected error during container start:")
            traceback.print_exc()
            try:
                if container is not None:
                    container.remove(force=True)
            except Exception:
                pass
            return None
        
    def is_running(self, container) -> bool:
        """Even when python code is visibly bugged, run command returns True",
        so we check container status directly."""
        try:
            container.reload()
            return container.status == "running"
        except Exception:
            return False


    def stop_and_remove(self) -> bool:
        """Stop and remove container by name (tag)."""
        if not self.client:
            print("FAIL: Docker client not initialized")
            return False

        try:
            print(f"\nSTOPPING and REMOVING container: {self.tag}")
            try:
                container = self.client.containers.get(self.tag)
            except NotFound:
                print(f"WARN: Container '{self.tag}' not found.")
                return False

            container.stop()
            container.remove()
            print(f"SUCCESS: Container '{self.tag}' stopped and removed.")
            return True

        except Exception:
            print("FAIL: Error while stopping/removing container:")
            traceback.print_exc()
            return False
