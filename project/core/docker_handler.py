from pathlib import Path
import traceback
import requests
import time
from requests.exceptions import RequestException
import docker
from docker.errors import DockerException, NotFound, ImageNotFound


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
        """Build Docker image from workdir with given tag.
           Should remove pre-existing images with the same tag"""
        if not self.client:
            print("FAIL: Docker client not initialized")
            return False
        self._remove_image_silent()
        try:
            print(f"\nBUILD Docker image: {self.tag}")
            image, logs = self.client.images.build(
                path=self.workdir,
                tag=self.tag,
                rm=True,
                forcerm=True,
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
        container = None
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
            for _ in range(15):  #!!! retry ~6s hızlandırmak için azaltılabilir ama bazı uygulamalarda kaçırma olacak
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
        """Stop and remove the container identified by self.tag.
 
        Does NOT remove the image; call full_cleanup() if you want both.
        """
        if not self.client:
            print("FAIL: Docker client not initialized")
            return False
 
        try:
            print(f"\nSTOPPING and REMOVING container: {self.tag}")
            try:
                container = self.client.containers.get(self.tag)
            except NotFound:
                print(f"WARN: Container '{self.tag}' not found (already removed?).")
                return True  # nothing to do, counts as success
 
            container.stop(timeout=10)
            container.remove(force=True)
            print(f"SUCCESS: Container '{self.tag}' stopped and removed.")
            return True
 
        except Exception:
            print("FAIL: Error while stopping/removing container:")
            traceback.print_exc()
            return False

    def remove_image(self) -> bool:
        """Remove the Docker image built for this run. Safe to call if missing."""
        if not self.client:
            return False
        try:
            self.client.images.remove(image=self.tag, force=True, noprune=False)
            print(f"SUCCESS: Image '{self.tag}' removed.")
            return True
        except ImageNotFound:
            print(f"WARN: Image '{self.tag}' not found (already removed?).")
            return True
        except Exception:
            print(f"FAIL: Could not remove image '{self.tag}':")
            traceback.print_exc()
            return False

    def full_cleanup(self) -> None:
        """Stop container + remove container + remove image. Call from every finally block."""
        self.stop_and_remove()
        self.remove_image()

    @staticmethod
    def prune_build_cache(client=None) -> None:
        """Delete all dangling build-cache objects. Equivalent to: docker builder prune -f"""
        try:
            c = client or docker.from_env()
            result = c.api.prune_builds()
            reclaimed = result.get("SpaceReclaimed", 0)
            print(f"INFO: Build cache pruned — {reclaimed / 1e6:.1f} MB reclaimed.")
        except Exception:
            print("WARN: Build cache prune failed (non-fatal):")
            traceback.print_exc()

    @staticmethod
    def prune_dangling_images(client=None) -> None:
        """Remove untagged/dangling images. Equivalent to: docker image prune -f"""
        try:
            c = client or docker.from_env()
            result = c.images.prune(filters={"dangling": True})
            reclaimed = result.get("SpaceReclaimed", 0)
            print(f"INFO: Dangling images pruned — {reclaimed / 1e6:.1f} MB reclaimed.")
        except Exception:
            print("WARN: Dangling image prune failed (non-fatal):")
            traceback.print_exc()

    def _remove_image_silent(self) -> None:
        """Remove image for self.tag without raising. Used before rebuild."""
        if not self.client:
            return
        try:
            self.client.images.remove(image=self.tag, force=True, noprune=False)
            print(f"INFO: Pre-existing image '{self.tag}' removed before rebuild.")
        except ImageNotFound:
            pass
        except Exception:
            print(f"WARN: Could not pre-remove image '{self.tag}' (non-fatal):")
            traceback.print_exc()