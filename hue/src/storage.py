import os
import random
import string
from abc import ABC, abstractmethod

import uuid
import json
from typing import Dict, Any

FILE_CREDENTIALS_PATH = os.getenv('FILE_CREDENTIALS_PATH', '/var/hue/')
FILE_CREDENTIALS_FILENAME = os.getenv('FILE_CREDENTIALS_FILENAME', 'credentials.json')


class AbstractCredentialsStore(ABC):
    @abstractmethod
    def generate_device_name(self) -> str:
        pass

    @abstractmethod
    def get_device_name(self) -> str:
        pass

    @abstractmethod
    def set_device_name(self, username) -> str:
        pass

    @abstractmethod
    def get_user_name(self) -> str:
        pass

    @abstractmethod
    def set_user_name(self, user_name) -> str:
        pass


class FileCredentialsStore(AbstractCredentialsStore):
    def generate_device_name(self) -> str:
        return ''.join(random.choice(string.ascii_letters) for i in range(32))

    def get_device_name(self) -> str:
        return self._load().get('device_name')

    def set_device_name(self, device_name) -> str:
        data = self._load()
        data['device_name'] = device_name
        return self._save(data).get('device_name')

    def get_user_name(self) -> str:
        return self._load().get('user_name')

    def set_user_name(self, user_name) -> str:
        data = self._load()
        data['user_name'] = user_name
        return self._save(data).get('user_name')

    @property
    def _full_path(self):
        return os.path.join(FILE_CREDENTIALS_PATH, FILE_CREDENTIALS_FILENAME)

    def _load(self) -> Dict[str, Any]:
        if not os.path.isfile(self._full_path):
            return dict(device_name=None, user_name=None)
        with open(self._full_path, 'r') as fh:
            contents = fh.read()
        return json.loads(contents)

    def _save(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not os.path.exists(os.path.dirname(self._full_path)):
            os.makedirs(os.path.dirname(self._full_path))
        with open(self._full_path, 'w') as fh:
            fh.write(json.dumps(data))
        return data
