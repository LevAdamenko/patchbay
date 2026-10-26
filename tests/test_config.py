from patchbay.config import Settings


def test_secrets_load_and_environment_wins(monkeypatch, tmp_path):
    secrets = tmp_path / "secrets.env"
    secrets.write_text("NEBIUS_API_KEY=from-file\nTAVILY_API_KEY=tavily-file\nLIVE=yes\n")
    monkeypatch.setenv("PATCHBAY_SECRETS_FILE", str(secrets))
    monkeypatch.setenv("NEBIUS_API_KEY", "from-env")

    settings = Settings()

    assert settings.nebius_api_key == "from-env"
    assert settings.tavily_api_key == "tavily-file"
    assert settings.live is True


def test_repr_masks_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("PATCHBAY_SECRETS_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv("NEBIUS_API_KEY", "very-secret-nebius")
    monkeypatch.setenv("TAVILY_API_KEY", "very-secret-tavily")

    rendered = repr(Settings())

    assert "very-secret" not in rendered
    assert "<set>" in rendered


def test_nemotron_max_tokens_config(monkeypatch, tmp_path):
    monkeypatch.setenv("PATCHBAY_SECRETS_FILE", str(tmp_path / "missing"))
    monkeypatch.delenv("NEMOTRON_MAX_TOKENS", raising=False)
    settings = Settings()
    assert settings.nemotron_max_tokens == 32768

    monkeypatch.setenv("NEMOTRON_MAX_TOKENS", "16384")
    settings_custom = Settings()
    assert settings_custom.nemotron_max_tokens == 16384

