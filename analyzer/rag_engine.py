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

    def search(self, query):
        query_words = {
            word.lower()
            for word in query.split()
            if len(word) > 2
        }

        results = []

        for document in self.load_documents():

            content_lower = document["content"].lower()

            score = sum(
                1
                for word in query_words
                if word in content_lower
            )

            if score > 0:
                results.append({
                    "source": document["source"],
                    "content": document["content"],
                    "score": score
                })

        results.sort(
            key=lambda result: result["score"],
            reverse=True
        )

        return results