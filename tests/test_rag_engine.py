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
    assert results[0]["source"] in {
        "mitre_attack.md",
        "ssh_attacks.md"
    }
    assert results[0]["score"] > 0


def test_search_finds_password_spraying_knowledge():

    engine = RAGEngine()

    results = engine.search(
        "SSH password spraying"
    )

    assert len(results) >= 1
    assert any(
        result["source"] in {
            "mitre_attack.md",
            "ssh_attacks.md"
        }
        for result in results
    )

    assert any(
        "password spraying" in result["content"].lower()
        for result in results
    )

def test_search_finds_powershell_knowledge():

    engine = RAGEngine()

    results = engine.search(
        "PowerShell execution"
    )

    assert len(results) >= 1

    assert any(
        result["source"] == "powershell_attacks.md"
        for result in results
    )

    assert any(
        "PowerShell" in result["content"]
        for result in results
    )    