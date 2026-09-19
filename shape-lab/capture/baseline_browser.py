#!/usr/bin/env python3
"""Ступень 1 (эталон cover-real): реальный браузер грузит origin как обычный
посетитель. БЕЗ тикета Construct -> relay уводит на honest-front cover, значит
на relay это выглядит как настоящий трафик сайта того же origin.

Запускать НА КЛИЕНТЕ параллельно с capture.sh <host> cover-real <secs>.
Один прогон = один визит; повторить N раз (разные времена) для N сессий.

  ./baseline_browser.py https://api.divany-kresla.uk --visits 1 --dwell 20
"""
import argparse, asyncio, random, sys

async def one_visit(origin, dwell):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        pg = await b.new_page()
        try:
            await pg.goto(origin, wait_until="networkidle", timeout=30000)
            # поскроллить/подождать как живой посетитель — короткие всплески + idle
            for _ in range(random.randint(2, 5)):
                await pg.mouse.wheel(0, random.randint(300, 1200))
                await asyncio.sleep(random.uniform(1.0, dwell / 3))
        except Exception as e:
            sys.stderr.write(f"visit warn: {e}\n")
        finally:
            await asyncio.sleep(random.uniform(1, 3))
            await b.close()

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("origin")
    ap.add_argument("--visits", type=int, default=1)
    ap.add_argument("--dwell", type=float, default=20.0, help="сек «жизни» визита")
    a = ap.parse_args()
    for i in range(a.visits):
        sys.stderr.write(f"visit {i+1}/{a.visits} -> {a.origin}\n")
        await one_visit(a.origin, a.dwell)
        await asyncio.sleep(random.uniform(1, 4))

if __name__ == "__main__":
    asyncio.run(main())
