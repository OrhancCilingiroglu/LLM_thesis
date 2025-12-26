import unittest
from unittest.mock import Mock, MagicMock, patch, call
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.docker_handler import DockerManager


class TestDockerManager(unittest.TestCase):
    """Unit tests for DockerManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.workdir = "/tmp/test_app"
        self.tag = "test_123"
        self.port = 8080

    @patch("core.docker_handler.DockerClient")
    def test_init_success(self, mock_docker_client):
        """Test successful initialization of DockerManager."""
        mock_client = MagicMock()
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)

        self.assertEqual(manager.tag, f"app_{self.tag}")
        self.assertEqual(manager.port, self.port)
        self.assertIsNotNone(manager.client)
        mock_docker_client.from_env.assert_called_once()

    @patch("core.docker_handler.DockerClient")
    def test_init_failure(self, mock_docker_client):
        """Test initialization when docker client fails."""
        mock_docker_client.from_env.side_effect = Exception("Docker daemon not running")

        manager = DockerManager(self.workdir, self.tag, self.port)

        # should still create manager but with None client
        self.assertEqual(manager.tag, f"app_{self.tag}")
        self.assertIsNone(manager.client)

    @patch("core.docker_handler.DockerClient")
    def test_build_image_success_high_level(self, mock_docker_client):
        """Test successful image build using high-level API."""
        mock_client = MagicMock()
        mock_image = MagicMock()
        mock_logs = [{"stream": "Step 1/5 : FROM python:3.9\n"}]

        mock_client.images.build.return_value = (mock_image, mock_logs)
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.build_image()

        self.assertTrue(result)
        mock_client.images.build.assert_called_once_with(
            path=manager.workdir, tag=manager.tag, rm=True
        )

    @patch("core.docker_handler.DockerClient")
    def test_build_image_failure(self, mock_docker_client):
        """Test image build failure."""
        mock_client = MagicMock()
        mock_client.images.build.side_effect = Exception("Build failed")
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.build_image()

        self.assertFalse(result)

    @patch("core.docker_handler.DockerClient")
    def test_build_image_no_client(self, mock_docker_client):
        """Test build_image when client is None."""
        mock_docker_client.from_env.side_effect = Exception("No docker")

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.build_image()

        self.assertFalse(result)

    @patch("core.docker_handler.DockerClient")
    def test_run_container_success_high_level(self, mock_docker_client):
        """Test successful container run using high-level API."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "abc123"

        mock_client.containers.run.return_value = mock_container
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.run_container()

        self.assertIsNotNone(result)
        self.assertEqual(result, mock_container)
        mock_client.containers.run.assert_called_once()

    @patch("core.docker_handler.DockerClient")
    def test_run_container_failure(self, mock_docker_client):
        """Test container run failure."""
        mock_client = MagicMock()
        mock_client.containers.run.side_effect = Exception("Run failed")
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.run_container()

        self.assertIsNone(result)

    @patch("core.docker_handler.DockerClient")
    def test_run_container_no_client(self, mock_docker_client):
        """Test run_container when client is None."""
        mock_docker_client.from_env.side_effect = Exception("No docker")

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.run_container()

        self.assertIsNone(result)

    @patch("core.docker_handler.DockerClient")
    def test_stop_and_remove_success(self, mock_docker_client):
        """Test successful container stop and remove."""
        mock_client = MagicMock()
        mock_container = MagicMock()

        mock_client.containers.get.return_value = mock_container
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.stop_and_remove()

        self.assertTrue(result)
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once()

    @patch("core.docker_handler.DockerClient")
    def test_stop_and_remove_container_not_found(self, mock_docker_client):
        """Test stop_and_remove when container not found."""
        mock_client = MagicMock()
        mock_client.containers.get.side_effect = Exception("Container not found")
        mock_client.api.remove_container.side_effect = Exception("Not found in API")
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.stop_and_remove()

        self.assertFalse(result)

    @patch("core.docker_handler.DockerClient")
    def test_stop_and_remove_no_client(self, mock_docker_client):
        """Test stop_and_remove when client is None."""
        mock_docker_client.from_env.side_effect = Exception("No docker")

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager.stop_and_remove()

        self.assertFalse(result)

    @patch("core.docker_handler.DockerClient")
    def test_has_highlevel_images_build_true(self, mock_docker_client):
        """Test _has_highlevel_images_build returns True."""
        mock_client = MagicMock()
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager._has_highlevel_images_build()

        self.assertTrue(result)

    @patch("core.docker_handler.DockerClient")
    def test_has_highlevel_images_build_false_no_client(self, mock_docker_client):
        """Test _has_highlevel_images_build returns False when client is None."""
        mock_docker_client.from_env.side_effect = Exception("No docker")

        manager = DockerManager(self.workdir, self.tag, self.port)
        result = manager._has_highlevel_images_build()

        self.assertFalse(result)

    @patch("core.docker_handler.DockerClient")
    def test_tag_naming_convention(self, mock_docker_client):
        """Test that tag is properly formatted with 'app_' prefix."""
        mock_client = MagicMock()
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager(self.workdir, "12345", self.port)

        self.assertEqual(manager.tag, "app_12345")

    @patch("core.docker_handler.DockerClient")
    def test_workdir_path_resolution(self, mock_docker_client):
        """Test that workdir is converted to absolute path."""
        mock_client = MagicMock()
        mock_docker_client.from_env.return_value = mock_client

        manager = DockerManager("./relative/path", self.tag, self.port)

        # Should be absolute path (not starting with .)
        self.assertTrue(os.path.isabs(manager.workdir))

    @patch("core.docker_handler.DockerClient")
    def test_port_assignment(self, mock_docker_client):
        """Test that port is correctly assigned."""
        mock_client = MagicMock()
        mock_docker_client.from_env.return_value = mock_client

        test_ports = [8080, 5000, 3000, 9000]
        for port in test_ports:
            manager = DockerManager(self.workdir, self.tag, port)
            self.assertEqual(manager.port, port)


if __name__ == "__main__":
    unittest.main()