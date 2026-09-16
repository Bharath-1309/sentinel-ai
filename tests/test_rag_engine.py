from analyzer.rag_engine import RAGEngine


def test_load_knowledge_documents():

    engine = RAGEngine()

    documents = engine.load_documents()

    assert len(documents) >= 1
    assert any(
        document["source"] == "mitre_attack.md"
        for document in documents
    )