from pymemcache.client.base import Client
from pymemcache.exceptions import MemcacheUnexpectedCloseError
import pickle


class Store:
    def __init__(self, address, port, timeout, retry_attempts=10):
        self._address = address
        self._port = port
        self._timeout = timeout
        self._client = None
        self._retry_attempts = retry_attempts

    @property
    def client(self):
        if not self._client:
            self._client = Client(
                (self._address, self._port),
                connect_timeout=self._timeout,
                timeout=self._timeout
            )
        return self._client

    def _send_query(self, name, *args, **kwargs):
        last_error = None
        for attempt in range(self._retry_attempts):
            try:
                return getattr(self.client, name)(*args, **kwargs)
            except MemcacheUnexpectedCloseError as e:
                last_error = e
                self._client = None
        raise last_error

    def get(self, key):
        return pickle.loads(self._send_query('get', key))

    def set(self, key, value):
        self._send_query('set', key, pickle.dumps(value))

    def cache_get(self, key):
        return self.get(key)

    def cache_set(self, key, value, expire):
        self._send_query('set', key, pickle.dumps(value), expire)


if __name__ == '__main__':
    s = Store('127.0.0.1', 1234, 10, 5)
    s.cache_set('x', 123, 5)
    # import time
    # time.sleep(10)
    print(s.get('x'))
