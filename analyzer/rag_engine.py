from pathlib import Path


class RAGEngine:

    def __init__(self, knowledge_dir="knowledge"):
        self.knowledge_dir = Path(knowledge_dir)

    def load_documents(self):
        documents = []

        for file_path in self.knowledge_dir.glob("*.md"):
            documents.append({
                "source": file_path.name,
                "content": file_path.read_text(
                    encoding="utf-8"
                )
            })

        return documents