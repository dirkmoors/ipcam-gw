import time
import uuid
from threading import Thread
from typing import Optional, NamedTuple

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



class NextActionThread(Thread):
    def __init__(self, username: str, group_number: int, after: int, on: Optional[bool]=None, bri: Optional[int]=None,
                 scene: Optional[str]=None, scene_name: Optional[str]=None, *args, **kwargs):
        super(NextActionThread, self).__init__(*args, **kwargs)

        self.username = username
        self.group_number = group_number
        self.after = after

        self.on = on
        self.bri = bri
        self.scene = scene
        self.scene_name = scene_name

    def run(self):
        print('NextActionThread.run')
        time.sleep(self.after)
        print('NextActionThread.run: NOW!')
        try:
            url = hue_api_url(f'{self.username}/groups/{self.group_number}/action')

            action = {}

            if self.on is not None:
                action['on'] = self.on

            if self.bri is not None:
                action['bri'] = self.bri

            if self.scene is not None:
                action['scene'] = self.scene
            elif self.scene_name is not None:
                action['scene'] = get_scene_by_name(self.scene_name)

            response = requests.put(url, json=action, verify=False)
            response.raise_for_status()
        finally:
            self.username = None
            self.group_number = None
            self.after = None

            self.on = None
            self.bri = None
            self.scene = None
            self.scene_name = None


        # e.g. http://0.0.0.0:8888/groups/4/action?scene_name=Oprit%20-%20Soft

@app.get("/groups/{group_number:int}/action")
def put_group_action(group_number: int, on: Optional[bool]=None, bri: Optional[int]=None, scene: Optional[str]=None,
                     scene_name: Optional[str]=None, next_on: Optional[bool]=None, next_bri: Optional[int]=None,
                     next_scene: Optional[str]=None, next_scene_name: Optional[str]=None, next_after: Optional[int]=10):
    username = get_or_create_username()

    url = hue_api_url(f'{username}/groups/{group_number}/action')

    action = {}

    if on is not None:
        action['on'] = on

    if bri is not None:
        action['bri'] = bri

    if scene is not None:
        action['scene'] = scene
    elif scene_name is not None:
        action['scene'] = get_scene_by_name(scene_name)

    response = requests.put(url, json=action, verify=False)
    response.raise_for_status()

    if next_on is not None or next_bri is not None or next_scene is not None or next_scene_name is not None:
        print('NextActionThread: creating....')
        NextActionThread(
            username=username, group_number=group_number, on=next_on, bri=next_bri, scene=next_scene,
            scene_name=next_scene_name, after=next_after).start()

    return response.json()


class SensorDefinition(BaseModel):
    name: str
    uniqueid: Optional[str] = None
    manufacturername: Optional[str] = 'DitchITall'
    modelid: Optional[str] = 'generic'
    swversion: Optional[str] = '1'
    devicetype: Optional[str] = 'CLIPPresence'


@app.post("/sensors/")
def create_new_virtual_sensor(definition: SensorDefinition):
    uniqueid = definition.uniqueid or str(uuid.uuid4()).replace('-', '')

    username = get_or_create_username()

    url = hue_api_url(f'{username}/sensors')

    print(definition)

    response = requests.post(url, json={
        'name': definition.name,
        'modelid': definition.modelid,
        'swversion': definition.swversion,
        'type': definition.devicetype,
        'uniqueid': uniqueid,
        'manufacturername': definition.manufacturername,
        'state': {
            'presence': False
        }
    }, verify=False)
    response.raise_for_status()

    return response.json()
