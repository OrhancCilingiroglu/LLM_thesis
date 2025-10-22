import docker
from pathlib import Path
import docker.errors
import traceback

class DockerManager:
    def __init__(self, workdir, tag, port):
        self.client = docker.from_env()
        self.workdir = str(Path(workdir).resolve())
        self.tag = f"app_{tag}" 
        self.port = port

    def build_image(self):
        try:
            print(f"\n🔨 BUILDING Docker image: {self.tag}")
            image, logs = self.client.images.build(path=self.workdir, tag=self.tag, rm=True)
            for chunk in logs:
                if 'stream' in chunk:
                    print(chunk['stream'].strip())
            print(f"SUCCESS : Docker image '{self.tag}' built successfully.")
            return True
        except Exception as e:
            print("FAIL : Docker build failed:")
            traceback.print_exc()
            return False

    def run_container(self):
        try:
            print(f"\n PROCESS : STARTING Docker container from image: {self.tag}")
            container = self.client.containers.run(
                image=self.tag,
                name=self.tag,
                ports={f"{self.port}/tcp": self.port},
                volumes={self.workdir: {"bind": "/app", "mode": "rw"}},
                detach=True
            )
            print(f"SUCCESS : Container '{self.tag}' started on port {self.port}")
            return container
        except docker.errors.APIError as e:
            print(f"FAIL : Failed to start container '{self.tag}': {e.explanation}")
            return None
        except Exception as e:
            print("FAIL : Unexpected error during container start:")
            traceback.print_exc()
            return None

    def stop_and_remove(self):
        try:
            print(f"\nPROCESS : STOPPING and REMOVING container: {self.tag}")
            container = self.client.containers.get(self.tag)
            container.stop()
            container.remove()   # bunlar test edilmeli bazen container name'ler çakışıyor demekki container silemiyor
            print(f"SUCCESS :  Container '{self.tag}' stopped and removed.")
            return True
        except docker.errors.NotFound:
            print(f"FAIL :  Container '{self.tag}' not found.")
            return False
        except Exception as e:
            print("FAIL :  Error while stopping/removing container:")
            traceback.print_exc()
            return False