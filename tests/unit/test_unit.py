import api  # предполагается, что api.py содержит метод method_handler
import datetime
import hashlib
import pytest


class MockStore:
    def __init__(self):
        self._cache = {}

    def get(self, name):
        return '["xxx"]'

    def cache_get(self, name):
        return self._cache.get(name)

    def cache_set(self, name, value, *args, **kwargs):
        self._cache[name] = value


@pytest.fixture
def handler_args():
    yield {
        'context': {},
        'headers': {},
        'store': MockStore()
    }


class TestSuite:
    # def setUp(self):
    #     self.context = {}
    #     self.headers = {}
    #     self.store = None

    def get_response(self, ctx, headers, store, request):
        res =  api.method_handler({"body": request, "headers": headers}, ctx, store)
        return res

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            request["token"] = hashlib.sha512(
                (datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')).hexdigest()
        else:
            msg = (request.get("account", "") + request.get("login", "") + api.SALT).encode('utf-8')
            request["token"] = hashlib.sha512(msg).hexdigest()

    def test_empty_request(self, handler_args):
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], {}
        )
        assert api.INVALID_REQUEST == code

    @pytest.mark.parametrize(
        ['method', 'cls'],
        [
            ('online_score', api.OnlineScoreHandler),
            ('clients_interests', api.ClientInterestHandler)
        ]
    )
    def test_good_method(self, method, cls):
        handler = api.create_request_handler(method)
        assert isinstance(handler, cls)

    def test_bad_method(self):
        with pytest.raises(ValueError):
            api.create_request_handler('bad_method')

    @pytest.mark.parametrize(
        ['req'],
        [
            ({"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},),
            ({"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},),
            ({"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}},)
        ]
    )
    def test_bad_auth(self, req, handler_args):
        _, code = self.get_response(handler_args['context'], handler_args['headers'], handler_args['store'], req)
        assert api.FORBIDDEN == code

    @pytest.mark.parametrize(
        ['req'],
        [
            ({"account": "horns&hoofs", "login": "h&f", "method": "online_score"},),
            ({"account": "horns&hoofs", "login": "h&f", "arguments": {}},),
            ({"account": "horns&hoofs", "method": "online_score", "arguments": {}},)
        ]
    )
    def test_invalid_method_request(self, req, handler_args):
        self.set_valid_auth(req)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], req
        )
        assert api.INVALID_REQUEST == code
        assert len(response)

    @pytest.mark.parametrize(
        ['args'],
        [
            ({},),
            ({"phone": "79175002040"},),
            ({"phone": "89175002040", "email": "stupnikov@otus.ru"},),
            ({"phone": "79175002040", "email": "stupnikovotus.ru"},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
              "first_name": 1},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
             "first_name": "s", "last_name": 2},),
            ({"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},),
            ({"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},)
        ])
    def test_invalid_score_request(self, args, handler_args):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": args}
        self.set_valid_auth(request)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], request
        )
        assert api.INVALID_REQUEST == code
        assert len(response)

    @pytest.mark.parametrize(
        ['args'],
        [
            ({"phone": "79175002040", "email": "stupnikov@otus.ru"},),
            ({"phone": 79175002040, "email": "stupnikov@otus.ru"},),
            ({"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},),
            ({"gender": 0, "birthday": "01.01.2000"},),
            ({"gender": 2, "birthday": "01.01.2000"},),
            ({"first_name": "a", "last_name": "b"},),
            ({"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
             "first_name": "a", "last_name": "b"},)
        ])
    def test_ok_score_request(self, args, handler_args):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": args}
        self.set_valid_auth(request)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], request
        )
        assert api.OK == code
        score = response.get("score")
        assert isinstance(score, (int, float)) and score >= 0
        assert (sorted(handler_args["context"]["has"]) == sorted(args.keys()))

    def test_ok_score_admin_request(self, handler_args):
        arguments = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
        request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], request
        )
        assert api.OK == code
        score = response.get("score")
        assert score == 42

    @pytest.mark.parametrize(
        ['args'],
        [
            ({},),
            ({"date": "20.07.2017"},),
            ({"client_ids": [], "date": "20.07.2017"},),
            ({"client_ids": {1: 2}, "date": "20.07.2017"},),
            ({"client_ids": ["1", "2"], "date": "20.07.2017"},),
            ({"client_ids": [1, 2], "date": "XXX"},)
        ]
    )
    def test_invalid_interests_request(self, args, handler_args):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": args}
        self.set_valid_auth(request)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], request
        )
        assert api.INVALID_REQUEST == code
        assert len(response)

    @pytest.mark.parametrize(
        ['args'],
        [
            ({"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},),
            ({"client_ids": [1, 2], "date": "19.07.2017"},),
            ({"client_ids": [0]},),
        ]
    )
    def test_ok_interests_request(self, args, handler_args):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": args}
        self.set_valid_auth(request)
        response, code = self.get_response(
            handler_args['context'], handler_args['headers'], handler_args['store'], request
        )
        assert api.OK == code
        assert len(args["client_ids"]) == len(response)
        for v in response.values():
            assert v
            assert isinstance(v, list)
            assert all(isinstance(i, (bytes, str)) for i in v)
        assert handler_args['context'].get("nclients") == len(args["client_ids"])
