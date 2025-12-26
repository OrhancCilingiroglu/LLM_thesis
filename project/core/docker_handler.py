from pathlib import Path
import traceback

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
            print(f"SUCCESS: Container '{self.tag}' started on port {self.port}")
            return container

        except Exception:
            print("FAIL: Unexpected error during container start:")
            traceback.print_exc()
            return None

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
