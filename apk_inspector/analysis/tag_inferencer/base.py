from abc import ABC, abstractmethod
from typing import Dict, List, Any

class BaseTagInferencer(ABC):
    @abstractmethod
    def infer_tags(self, data: Dict[str, Any]) -> List[str]:
        pass
