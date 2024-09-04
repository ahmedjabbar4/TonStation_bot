import asyncio
from urllib.parse import unquote, quote
import urllib.parse

from random import randint

from time import time
import aiohttp
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from pyrogram import Client
from pyrogram.errors import Unauthorized, UserDeactivated, AuthKeyUnregistered, FloodWait
from pyrogram.raw.functions.messages import RequestAppWebView, RequestWebView
from pyrogram.raw import types
from .agents import generate_random_user_agent

from typing import Callable
import functools

from bot.utils import logger, utils
from bot.exceptions import InvalidSession
from .headers import headers, random_string
from bot.config import settings


def error_handler(func: Callable):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            await asyncio.sleep(1)

    return wrapper


class Tapper:
    def __init__(self, tg_client: Client, proxy: str | None):
        self.session_name = tg_client.name
        self.proxy = proxy
        self.tg_client = tg_client
        self.bot_name = 'tonstationgames_bot'  # Bot login
        self.app_url = 'https://tonstation.app/app/'  # webapp host
        self.api_endpoint = 'https://tonstation.app'

        self.user = None
        self.token = None
        self.errors = 0

        self.farming_end = None

    async def get_tg_web_data(self):
        if self.proxy:
            proxy = Proxy.from_str(self.proxy)
            proxy_dict = dict(
                scheme=proxy.protocol,
                hostname=proxy.host,
                port=proxy.port,
                username=proxy.login,
                password=proxy.password
            )
        else:
            proxy_dict = None

        self.tg_client.proxy = proxy_dict

        try:
            with_tg = True

            if not self.tg_client.is_connected:
                with_tg = False
                try:
                    await self.tg_client.connect()
                except (Unauthorized, UserDeactivated, AuthKeyUnregistered):
                    raise InvalidSession(self.session_name)

            while True:
                try:
                    peer = await self.tg_client.resolve_peer(self.bot_name)
                    break
                except FloodWait as fl:
                    fls = fl.value

                    logger.warning(f"<light-yellow>{self.session_name}</light-yellow> | FloodWait {fl}")
                    logger.info(f"<light-yellow>{self.session_name}</light-yellow> | Sleep {fls}s")

                    await asyncio.sleep(fls + 3)

            if settings.REF_ID == '':
                start_param = ''  # ref
                self.start_param = ''  # ref
            else:
                start_param = settings.REF_ID
                self.start_param = start_param

            web_view = await self.tg_client.invoke(RequestWebView(
                peer=peer,
                bot=peer,
                platform='android',
                from_bot_menu=False,
                url=self.app_url
            ))

            auth_url = web_view.url

            tg_web_data = unquote(
                string=unquote(
                    string=auth_url.split('tgWebAppData=', maxsplit=1)[1].split('&tgWebAppVersion', maxsplit=1)[0]))

            self.user = await self.tg_client.get_me()

            if with_tg is False:
                await self.tg_client.disconnect()

            return tg_web_data

        except InvalidSession as error:
            raise error

        except Exception as error:
            logger.error(
                f"<light-yellow>{self.session_name}</light-yellow> | Error while Get TG web data: {error}")
            await asyncio.sleep(delay=3)

    @error_handler
    async def make_request(self, http_client, method, endpoint=None, url=None, **kwargs):
        try:
            full_url = url or f"{self.api_endpoint}{endpoint or ''}"
            response = await http_client.request(method, full_url, **kwargs)

            return await response.json()
        except aiohttp.ClientResponseError as error:
            self.errors += 1
            logger.error(f"{self.session_name} | HTTP error: {error}")
            await asyncio.sleep(delay=3)

    @error_handler
    async def check_proxy(self, http_client: aiohttp.ClientSession) -> None:
        response = await self.make_request(http_client, 'GET', url='https://httpbin.org/ip',
                                           timeout=aiohttp.ClientTimeout(5))
        ip = response.get('origin')
        logger.info(f"{self.session_name} | Proxy IP: {ip}")

    @error_handler
    async def auth(self, http_client):
        tg_web_data = await self.get_tg_web_data()
        parsed_query = urllib.parse.parse_qs(tg_web_data)
        encoded_query = urllib.parse.urlencode(parsed_query, doseq=True)

        response = await self.make_request(http_client, "POST", "/userprofile/api/v1/users/auth", json={'initData':f'{encoded_query}'})

        if response.get('code') != 403:
            self.token = response.get('accessToken')

            http_client.headers["Authorization"] = f"Bearer {self.token}"
            headers["Authorization"] = f"Bearer {self.token}"
            return response
        else:
            logger.info(f"{self.session_name} | Error while getting token: {response.get('message')}")


    @error_handler
    async def login(self, http_client):
        response = await self.make_request(http_client, "POST", "/user-rates/login", json={'userId': self.user.id})
        return response

    @error_handler
    async def get_farm_status(self, http_client):
        response = await self.make_request(http_client, "GET", f"/farming/api/v1/farming/{self.user.id}/running")
        return response

    @error_handler
    async def get_tasks(self, http_client):
        response = await self.make_request(http_client, "GET", f"/farming/api/v1/tasks")
        return response
    @error_handler
    async def start_farm(self, http_client):
        payload = {'userId': f'{self.user.id}', 'taskId': '1'}
        response = await self.make_request(http_client, "POST", '/farming/api/v1/farming/start', json=payload)
        return response

    async def run(self) -> None:
        if settings.USE_RANDOM_DELAY_IN_RUN:
            random_delay = randint(settings.RANDOM_DELAY_IN_RUN[0], settings.RANDOM_DELAY_IN_RUN[1])
            logger.info(f"{self.tg_client.name} | Run for <lw>{random_delay}s</lw>")

            await asyncio.sleep(delay=random_delay)

        proxy_conn = ProxyConnector().from_url(self.proxy) if self.proxy else None
        http_client = CloudflareScraper(headers=headers, connector=proxy_conn)

        if self.proxy:
            await self.check_proxy(http_client=http_client)

        if settings.FAKE_USERAGENT:
            http_client.headers['User-Agent'] = generate_random_user_agent(device_type='android', browser_type='chrome')

        while True:
            if self.errors >= settings.ERRORS_BEFORE_STOP:
                logger.error(f"{self.session_name} | Bot stopped (too many errors)")
                break
            try:
                if http_client.closed:
                    if proxy_conn:
                        if not proxy_conn.closed:
                            proxy_conn.close()

                    proxy_conn = ProxyConnector().from_url(self.proxy) if self.proxy else None
                    http_client = CloudflareScraper(headers=headers, connector=proxy_conn)
                    if settings.FAKE_USERAGENT:
                        http_client.headers['User-Agent'] = generate_random_user_agent(device_type='android',
                                                                                       browser_type='chrome')

                if not self.token:
                    access_token = await self.auth(http_client=http_client)

                    if access_token.get('code') == 403:
                        logger.info(f"{self.session_name} | Failed login")
                        logger.info(f"{self.session_name} | Sleep <light-red>300s</light-red>")
                        await asyncio.sleep(delay=300)
                        continue
                    else:
                        logger.info(f"{self.session_name} | <light-red>Login successful</light-red>")


                farm_status = await self.get_farm_status(http_client=http_client)

                if farm_status.get('data'):
                    self.farming_end = utils.convert_to_local_and_unix(farm_status.get('data', [])[0].get('timeEnd'))
                    is_claimed = farm_status.get('data', [])[0].get('isClaimed')

                    if time() > self.farming_end and is_claimed is False:
                        print('need a claim')
                    else:
                        logger.info(f"{self.session_name} | Farming in progress, next claim in {round((self.farming_end - time()) / 60, 2)} min")

                else:
                    print('start farm')
                    start = await self.start_farm(http_client=http_client)
                    print(start)


                # Close connection & reset token
                await http_client.close()
                # self.token = None

                sleep_time = self.farming_end - time()
                logger.info(f'<light-yellow>{self.session_name}</light-yellow> | sleep {round(sleep_time / 60, 2)} min')
                await asyncio.sleep(sleep_time)

            except InvalidSession as error:
                raise error

            except Exception as error:
                logger.error(f"<light-yellow>{self.session_name}</light-yellow> | Unknown error: {error}")
                await asyncio.sleep(delay=3)


async def run_tapper(tg_client: Client, proxy: str | None):
    try:
        await Tapper(tg_client=tg_client, proxy=proxy).run()
    except InvalidSession:
        logger.error(f"{tg_client.name} | Invalid Session")
