"""
Tests for Felipinho AI Service and Assistant Router (morfeusec OSINT)
"""
import asyncio
from app.services.felipinho_service import felipinho_service


def test_felipinho_ai_mobile_query():
    async def run():
        res = await felipinho_service.answer_query("Como interpretar o score MASVS do APK?")
        assert res["assistant"] == "Felipinho AI"
        assert "OWASP MASVS" in res["response"]
        assert len(res["suggested_actions"]) > 0

    asyncio.run(run())


def test_felipinho_ai_dmarc_query():
    async def run():
        res = await felipinho_service.answer_query("O que significa DMARC p=reject?")
        assert res["assistant"] == "Felipinho AI"
        assert "p=reject" in res["response"]

    asyncio.run(run())


def test_felipinho_ai_author_query():
    async def run():
        res = await felipinho_service.answer_query("Quem é o autor do morfeusec OSINT?")
        assert "Felipe Costa" in res["response"]
        assert "felipe_c@myyahoo.com" in res["response"]

    asyncio.run(run())
