# ai-engine

Moteur IA de CodeGate : explication et triage (cahier §5.6, §9.4). L'analyse
déterministe (secrets, dépendances, SAST) se fait en amont ; ce service rend
les risques compréhensibles — il ne décide **jamais** autoriser/bloquer.

## Lancer en local

```bash
cd services/ai-engine
python -m venv .venv && . .venv/Scripts/activate   # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

`POST /explain` prend un finding et renvoie une explication en langage clair.
Sans `ANTHROPIC_API_KEY`, l'explication est déterministe (templates) ; avec la
clé, elle est enrichie par Claude (Haiku).
