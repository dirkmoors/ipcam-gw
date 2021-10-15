from typing import Optional

import os
from urllib.parse import urljoin

import requests
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import JSONResponse

from storage import FileCredentialsStore

HUE_BRIDGE_IP = os.getenv('HUE_BRIDGE_IP')

app = FastAPI()

storage = FileCredentialsStore()


def hue_api_url(path: str = ''):
    return urljoin(f'https://{HUE_BRIDGE_IP}/api/', path)


class NotYetConfirmed(Exception):
    pass


def raise_link_not_ressed():
    raise NotYetConfirmed('You did not confirm this application. Please click the Hue Bridge link button!')


def verify_or_raise_link_not_pressed_response(response, expected_status_code=200):
    assert response.status_code == expected_status_code
    data = response.json()
    if 'error' in data[0] and data[0]['error']['description'] == 'link button not pressed':
        raise_link_not_ressed()


def get_or_create_username():
    username = storage.get_user_name()
    devicename = storage.get_device_name()

    if not username:
        if not devicename:
            devicename = storage.generate_device_name()

        response = requests.post(hue_api_url(), json={
            'devicetype': devicename
        }, verify=False)
        response.raise_for_status()

        try:
            verify_or_raise_link_not_pressed_response(response)
        except NotYetConfirmed as e:
            storage.set_device_name(devicename)
            raise e

        data = response.json()
        if 'success' in data[0]:
            username = data[0]['success']['username']
            storage.set_user_name(username)

    return username


@app.get("/user/")
def get_user():
    try:
        return {"user": get_or_create_username()}
    except NotYetConfirmed as e:
        return {'error': str(e)}


@app.get("/groups/")
def get_groups():
    username = get_or_create_username()

    url = hue_api_url(f'{username}/groups')

    response = requests.get(url, verify=False)
    response.raise_for_status()


    return response.json()


@app.get("/groups/{group_number:int}/")
def get_group(group_number: int):
    username = get_or_create_username()

    url = hue_api_url(f'{username}/groups/{group_number}')

    response = requests.get(url, verify=False)
    response.raise_for_status()


    return response.json()





@app.get("/scenes/")
def get_scenes():
    username = get_or_create_username()

    url = hue_api_url(f'{username}/scenes')

    response = requests.get(url, verify=False)
    response.raise_for_status()


    return response.json()


class UnknownScene(Exception):
    pass


@app.exception_handler(UnknownScene)
async def unknown_scene_exception_handler(request: Request, exc: UnknownScene):
    return JSONResponse(
        status_code=404,
        content={"error": str(exc)},
    )


def get_scene_by_name(scene_name: str) -> str:
    scenes = get_scenes()
    for scene_id in scenes.keys():
        if scenes[scene_id]['name'] == scene_name:
            return scene_id
    raise UnknownScene(f'Unknown scene: {scene_name}')



# e.g. http://0.0.0.0:8888/groups/4/action?scene_name=Oprit%20-%20Soft

@app.get("/groups/{group_number:int}/action")
def put_group_action(group_number: int, on: Optional[bool]=None, bri: Optional[int]=None, scene: Optional[str]=None,
                     scene_name: Optional[str]=None):
    username = get_or_create_username()

    url = hue_api_url(f'{username}/groups/{group_number}/action')

    action = {}

    if on is not None:
        action['on'] = on

    if bri is not None:
        action['bri'] = bri

    if scene is not None:
        action['scene'] = scene

    if scene_name is not None:
        action['scene'] = get_scene_by_name(scene_name)

    response = requests.put(url, json=action, verify=False)
    response.raise_for_status()

    return response.json()
