from analyzer.rag_engine import RAGEngine


def test_load_knowledge_documents():

    engine = RAGEngine()

    documents = engine.load_documents()

    assert len(documents) >= 1
    assert any(
        document["source"] == "mitre_attack.md"
        for document in documents
    )
def test_search_finds_brute_force_knowledge():

    engine = RAGEngine()

    results = engine.search(
        "SSH brute force"
    )

    assert len(results) >= 1
    assert results[0]["source"] == "mitre_attack.md"
    assert results[0]["score"] > 0