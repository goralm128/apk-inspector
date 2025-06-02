from tools.adb_tools import (
    wake_and_unlock,
    launch_app,
    force_stop_app,
    is_device_awake
)
from apk_inspector.utils.logger import get_logger

logger = get_logger()


class AppController:
    """
    Controls the Android app lifecycle on a connected device.
    Handles wake/unlock, app launch, and cleanup operations.
    """

    def __init__(self, package_name: str):
        self.package = package_name

    def prepare_device(self):
        """Wakes the device and unlocks it before launching the app."""
        if not is_device_awake():
            logger.info("[INFO] Device is asleep, waking up...")
            wake_and_unlock()
        self.launch()

    def launch(self):
        """Launches the app by its package name."""
        logger.info(f"[INFO] Preparing to launch app: {self.package}")
        launch_app(self.package)

    def cleanup(self):
        """Stops the app after tracing is done."""
        logger.info(f"[INFO] Stopping app: {self.package}")
        force_stop_app(self.package)
