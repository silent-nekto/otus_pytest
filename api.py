#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import inspect
import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(abc.ABC):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    @abc.abstractmethod
    def check_value(self, value): ...


class CharField(Field):
    def check_value(self, value):
        if not isinstance(value, str):
            raise ValueError(f'Value must be string: {value}')
        if not value and not self.nullable:
            raise ValueError('Value must not be empty')
        return value


class ArgumentsField(Field):
    def check_value(self, value):
        return value


class EmailField(Field):
    def check_value(self, value):
        if '@' not in value:
            raise ValueError(f'Email has incorrect format {value}')
        return value


class PhoneField(Field):
    def check_value(self, value):
        if not isinstance(value, (int, str)):
            raise ValueError(f'Invalid type of phone number "{type(value)}", expected string or integer')
        if not re.match(r'^7\d{10}$', str(value)):
            raise ValueError(f'Phone number has incorrect format {value}')
        return str(value)


class ParsableDateField(abc.ABC):
    @staticmethod
    def parse(value):
        return datetime.datetime.strptime(value, '%d.%m.%Y')

class DateField(Field, ParsableDateField):
    def check_value(self, value):
        return self.parse(value)


class BirthDayField(Field, ParsableDateField):
    def check_value(self, value):
        current = datetime.datetime.now()
        latest = datetime.datetime(current.year - 70, current.month, current.day)
        bd = self.parse(value)
        if bd < latest:
            raise ValueError(f'Age is more than 70 years')
        return bd


class GenderField(Field):
    def check_value(self, value):
        if value not in [0, 1, 2]:
            raise ValueError(f'Gender has invalid value: {value}')
        return value


class ClientIDsField(Field):
    def check_value(self, value):
        if not isinstance(value, list):
            raise ValueError(f'Value must be list: {value}')
        if not value:
            raise ValueError('Value must not be empty')
        for client_id in value:
            if not isinstance(client_id, int):
                raise ValueError(f'ClientId {client_id} must be integer')
        return value


class BaseRequest:
    def __init__(self):
        self._fields = {}
        for name, value in inspect.getmembers(self):
            if isinstance(value, Field):
                self._fields[name] = value

    def enum_fields(self):
        for name in self._fields:
            yield name, getattr(self, name)

    def fill(self, data):
        for name, field in self._fields.items():
            if name not in data:
                if field.required:
                    raise ValueError(f'Field "{name}" is required')
                setattr(self, name, None)
            else:
                checked = field.check_value(data[name])
                setattr(self, name, checked)

    def not_empty(self, name):
        value = getattr(self, name)
        res = value not in ['', [], {}, None]
        return res


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def fill(self, data):
        super().fill(data)
        if None not in [self.phone, self.email] and self.not_empty('phone') and self.not_empty('email'):
            return
        if None not in [self.first_name, self.last_name] and self.not_empty('first_name') and self.not_empty('last_name'):
            return
        if None not in [self.gender, self.birthday] and self.not_empty('gender') and self.not_empty('birthday'):
            return
        raise ValueError(f'Incorrect request: {data}')


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class RequestHandler(abc.ABC):
    @abc.abstractmethod
    def process(self, request, ctx, store): ...


class OnlineScoreHandler(RequestHandler):
    def process(self, request, ctx, store):
        p = OnlineScoreRequest()
        p.fill(request.arguments)
        ctx['has'] = [name for name, value in p.enum_fields() if p.not_empty(name) and value is not Ellipsis]
        score = 42
        if not request.is_admin:
            score = scoring.get_score(store, p.phone, p.email, p.birthday, p.gender, p.first_name, p.last_name)
        return {'score': score}


class ClientInterestHandler(RequestHandler):
    def process(self, request, ctx, store):
        p = ClientsInterestsRequest()
        p.fill(request.arguments)
        ctx['nclients'] = len(p.client_ids)
        result = {}
        for client in p.client_ids:
            result[client] = scoring.get_interests(store, client)
        return result


def create_request_handler(method):
    if method == 'online_score':
        return OnlineScoreHandler()
    elif method == 'clients_interests':
        return ClientInterestHandler()
    else:
        raise ValueError(f'Unknown method: {method}')


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    r = MethodRequest()
    try:
        r.fill(request['body'])
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    if not check_auth(r):
        return ERRORS[FORBIDDEN], FORBIDDEN

    try:
        handler = create_request_handler(r.method)
    except ValueError as e:
        logging.exception(f'Failed to create request handler: {e}')
        return ERRORS[NOT_FOUND], NOT_FOUND

    try:
        result = handler.process(r, ctx, store)
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    return result, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()