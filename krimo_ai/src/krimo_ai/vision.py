from __future__ import annotations

import base64
import io
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


@dataclass
class VisionResult:
    success: bool
    description: str = ""
    analysis: Optional[Dict[str, Any]] = None
    text: str = ""
    error: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "description": self.description,
            "analysis": self.analysis,
            "text": self.text,
            "error": self.error,
            "confidence": self.confidence,
        }


class ImageProcessor:
    def __init__(self):
        self.supported_formats = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"}

    def load_image(self, path: Union[str, Path]) -> Optional[Any]:
        if not PIL_AVAILABLE:
            return None
        try:
            return Image.open(path)
        except Exception:
            return None

    def load_from_bytes(self, data: bytes) -> Optional[Any]:
        if not PIL_AVAILABLE:
            return None
        try:
            return Image.open(io.BytesIO(data))
        except Exception:
            return None

    def load_from_base64(self, data: str) -> Optional[str]:
        try:
            image_data = base64.b64decode(data)
            return self.load_from_bytes(image_data)
        except Exception:
            return None

    def resize(self, image: Any, max_size: Tuple[int, int]) -> Optional[Any]:
        if not PIL_AVAILABLE:
            return None
        try:
            image.thumbnail(max_size, Image.Resampling.LANCZOS)
            return image
        except Exception:
            return None

    def to_base64(self, image: Any, format: str = "PNG") -> Optional[str]:
        if not PIL_AVAILABLE:
            return None
        try:
            buffer = io.BytesIO()
            image.save(buffer, format=format)
            return base64.b64encode(buffer.getvalue()).decode("utf-8")
        except Exception:
            return None

    def to_bytes(self, image: Any, format: str = "PNG") -> Optional[bytes]:
        if not PIL_AVAILABLE:
            return None
        try:
            buffer = io.BytesIO()
            image.save(buffer, format=format)
            return buffer.getvalue()
        except Exception:
            return None

    def get_info(self, image: Any) -> Dict[str, Any]:
        if not PIL_AVAILABLE or image is None:
            return {}
        return {
            "width": image.width,
            "height": image.height,
            "mode": image.mode,
            "format": image.format,
        }


class OCRProcessor:
    def __init__(self):
        self.languages = ["eng"]

    def extract_text(self, image: Any) -> str:
        if not OCR_AVAILABLE or not PIL_AVAILABLE:
            return ""
        try:
            return pytesseract.image_to_string(image)
        except Exception:
            return ""

    def extract_text_with_boxes(self, image: Any) -> List[Dict[str, Any]]:
        if not OCR_AVAILABLE or not PIL_AVAILABLE:
            return []
        try:
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            results = []
            for i in range(len(data["text"])):
                if data["text"][i].strip():
                    results.append({
                        "text": data["text"][i],
                        "confidence": float(data["conf"][i]),
                        "left": data["left"][i],
                        "top": data["top"][i],
                        "width": data["width"][i],
                        "height": data["height"][i],
                    })
            return results
        except Exception:
            return []

    def detect_language(self, text: str) -> str:
        if not text.strip():
            return "unknown"
        try:
            from langdetect import detect
            return detect(text)
        except Exception:
            return "unknown"


class ScreenshotTool:
    def __init__(self):
        self.platform = os.name

    def capture_window(self, window_title: Optional[str] = None) -> Optional[bytes]:
        if self.platform == "nt":
            return self._capture_windows(window_title)
        return self._capture_linux(window_title)

    def _capture_windows(self, window_title: Optional[str] = None) -> Optional[bytes]:
        try:
            import mss
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                return mss.tools.to_bytes(screenshot)
        except Exception:
            return None

    def _capture_linux(self, window_title: Optional[str] = None) -> Optional[bytes]:
        try:
            import mss
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                return mss.tools.to_bytes(screenshot)
        except Exception:
            return None


class VisionAnalyzer:
    def __init__(
        self,
        model_func: Optional[Any] = None,
        use_ollama: bool = True,
        ollama_endpoint: str = "http://127.0.0.1:11434",
        vision_model: str = "llava",
    ):
        self.model_func = model_func
        self.use_ollama = use_ollama
        self.ollama_endpoint = ollama_endpoint
        self.vision_model = vision_model
        self.image_processor = ImageProcessor()
        self.ocr = OCRProcessor()
        self.screenshot = ScreenshotTool()

    def _prepare_image_for_api(self, image: Any) -> Optional[str]:
        return self.image_processor.to_base64(image)

    def _analyze_with_ollama(self, image: Any, prompt: str = "Describe this image in detail.") -> VisionResult:
        if not self.use_ollama:
            return VisionResult(success=False, error="Ollama not enabled")

        import requests

        image_b64 = self._prepare_image_for_api(image)
        if not image_b64:
            return VisionResult(success=False, error="Failed to process image")

        try:
            response = requests.post(
                f"{self.ollama_endpoint}/api/generate",
                json={
                    "model": self.vision_model,
                    "prompt": prompt,
                    "images": [image_b64],
                    "stream": False,
                },
                timeout=60,
            )
            response.raise_for_status()
            result = response.json()
            return VisionResult(
                success=True,
                description=result.get("response", ""),
                confidence=0.85,
            )
        except Exception as e:
            return VisionResult(success=False, error=str(e))

    def analyze(self, image: Any, prompt: str = "Describe this image in detail.") -> VisionResult:
        if self.use_ollama:
            return self._analyze_with_ollama(image, prompt)
        return VisionResult(success=False, error="No vision backend configured")

    def describe_image(self, path: Union[str, Path]) -> VisionResult:
        path_obj = Path(path) if not isinstance(path, Path) else path
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        if not path_obj.exists():
            return VisionResult(success=False, error=f"File not found: {path_obj}")
        image = self.image_processor.load_image(path_obj)
        if not image:
            return VisionResult(success=False, error=f"Failed to load image: {path_obj}")
        return self.analyze(image)

    def describe_image_bytes(self, data: bytes) -> VisionResult:
        image = self.image_processor.load_from_bytes(data)
        if not image:
            return VisionResult(success=False, error="Failed to load image from bytes")
        return self.analyze(image)

    def read_text_from_image(self, path: Union[str, Path]) -> VisionResult:
        path_obj = Path(path) if not isinstance(path, Path) else path
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        if not path_obj.exists():
            return VisionResult(success=False, error=f"File not found: {path_obj}")
        image = self.image_processor.load_image(path_obj)
        if not image:
            return VisionResult(success=False, error="Failed to load image")
        text = self.ocr.extract_text(image)
        return VisionResult(
            success=bool(text.strip()),
            text=text,
            description=f"Extracted {len(text)} characters",
        )

    def find_text_in_image(self, path: Union[str, Path], search_text: str) -> List[Dict[str, Any]]:
        path_obj = Path(path) if not isinstance(path, Path) else path
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        if not path_obj.exists():
            return []
        image = self.image_processor.load_image(path_obj)
        if not image:
            return []
        boxes = self.ocr.extract_text_with_boxes(image)
        matches = []
        search_lower = search_text.lower()
        for box in boxes:
            if search_lower in box["text"].lower():
                matches.append(box)
        return matches


class VisionCapabilities:
    def __init__(
        self,
        model_func: Optional[Any] = None,
        ollama_endpoint: str = "http://127.0.0.1:11434",
    ):
        self.analyzer = VisionAnalyzer(
            model_func=model_func,
            use_ollama=True,
            ollama_endpoint=ollama_endpoint,
        )
        self.screenshot = ScreenshotTool()

    def analyze_image_file(self, path: str) -> VisionResult:
        if not PIL_AVAILABLE:
            return VisionResult(success=False, error="Pillow not installed. Run: pip install pillow")
        return self.analyzer.describe_image(path)

    def analyze_screenshot(self, prompt: Optional[str] = None) -> VisionResult:
        screenshot_data = self.screenshot.capture_window()
        if not screenshot_data:
            return VisionResult(success=False, error="Failed to capture screenshot")
        image = self.analyzer.image_processor.load_from_bytes(screenshot_data)
        if not image:
            return VisionResult(success=False, error="Failed to process screenshot")
        return self.analyzer.analyze(image, prompt or "Describe what you see on screen.")

    def extract_text_from_image(self, path: str) -> VisionResult:
        if not PIL_AVAILABLE:
            return VisionResult(success=False, error="Pillow not installed. Run: pip install pillow")
        if not OCR_AVAILABLE:
            return VisionResult(success=False, error="pytesseract not installed. Run: pip install pytesseract")
        return self.analyzer.read_text_from_image(path)

    def find_text_in_image(self, path: str, text: str) -> List[Dict[str, Any]]:
        return self.analyzer.find_text_in_image(path, text)
