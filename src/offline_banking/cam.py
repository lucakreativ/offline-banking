from ctypes import cdll
from rubicon.objc import NSObject, objc_method


av_foundation = cdll.LoadLibrary("AVFoundation")


class CameraService(NSObject):
    @objc_method
    def start(self, delegate):
        self.delegate = delegate

    @objc_method
    def setup_camera(self):