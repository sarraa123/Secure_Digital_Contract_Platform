def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Secure Digital Contract Platform - OK" in response.data