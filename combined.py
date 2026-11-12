import asyncio
import os

import uvicorn

from api import app as api_app
from app import build_application


async def main():
    bot = build_application()
    await bot.initialize()
    await bot.start()
    await bot.updater.start_polling()

    server = uvicorn.Server(
        uvicorn.Config(
            api_app,
            host='0.0.0.0',
            port=int(os.getenv('PORT', '10000')),
            log_level='info',
        )
    )
    try:
        await server.serve()
    finally:
        await bot.updater.stop()
        await bot.stop()
        await bot.shutdown()


if __name__ == '__main__':
    asyncio.run(main())
