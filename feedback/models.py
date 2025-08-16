from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime

@dataclass
class FeedbackEntry:
    id_artigo: str
    prompt: str
    avaliacao: int  # 1=positivo, 0=negativo
    comentario: Optional[str]
    timestamp: str

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def now():
        return datetime.utcnow().isoformat() 