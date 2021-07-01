import json
from io import BytesIO

# Install wheel from https://www.lfd.uci.edu/~gohlke/pythonlibs/#pycurl
import pycurl


class Response:
    body = None
    status_code = None

    def __init__(self):
        self.body = None
        self.status_code = None

    def json(self):
        try:
            return json.loads(self.body)
        except:
            return self.body

    def print(self):
        try:
            s = "HTTP " + str(self.status_code) + "\n" + json.dumps(json.loads(self.body), indent=4)
            print(s)
            return s
        except:
            s = "HTTP " + str(self.status_code) + "\n" + self.body
            print(s)
            return s

    def __repr__(self):
        return self.print()


class CurlX:

    def __init__(self, proxy=None, auth=None, cookies=None, verify=None, debug=False):
        self.buffer = None
        # initialize http streams
        self.c = pycurl.Curl()
        self.url = None
        self.response = Response()
        self.debug = debug

        # set user & password for basic authentication
        self.set_auth(auth)
        # set certificate authority for https or does not verify (insecure)
        self.set_verify(verify)

        self.proxy_url = None
        self.proxy_auth = None
        self.set_proxy(proxy)

        self.set_cookies(cookies)
        self.cookies = cookies

    def get(self, url, headers=None, proxy=None, auth=None, cookies=None, verify=None):
        self.buffer = BytesIO()
        self.c.setopt(self.c.WRITEDATA, self.buffer)
        self.c.setopt(self.c.URL, url)
        self.set_cookies(cookies)
        self.set_header(headers)
        self.set_proxy(proxy)
        self.set_verify(verify)
        self.set_auth(auth)
        self.c.setopt(self.c.CUSTOMREQUEST, "GET")
        if self.debug:
            self.c.setopt(self.c.VERBOSE, 1)
        try:
            self.c.perform()
        except pycurl.error as e:
            self.response.body = str(e)
            self.response.status_code = -1
            return self.response
        _body = self.buffer.getvalue()

        self.response.status_code = self.c.getinfo(self.c.HTTP_CODE)
        if self.response.status_code == 200:
            _r = _body.decode('utf-8')
            # check for multiple json objects and convert to a list
            try:
                _resp = json.loads(_r)
            except:
                _r = '[' + _r.replace('}{', '},{') + ']'
            self.response.body = _r
        else:
            self.response.body = _body
        return self.response

    def put(self, url, data, headers=None, proxy=None, auth=None, cookies=None, verify=None):
        self.buffer = BytesIO()
        self.c.setopt(self.c.WRITEDATA, self.buffer)
        self.c.setopt(self.c.URL, url)
        self.set_cookies(cookies)
        self.set_proxy(proxy)
        self.set_verify(verify)
        self.set_auth(auth)
        self.c.setopt(self.c.POSTFIELDS, "")
        self.c.setopt(self.c.HTTPPOST, None)

        if headers:
            self.set_header(headers)
        else:
            self.c.setopt(self.c.HTTPHEADER, ['Content-Type: application/json', 'Accept: application/json'])

        if data:
            if type(data) is dict:
                _data = json.dumps(data)
            else:
                _data = data
            self.c.setopt(self.c.POSTFIELDS, _data)

        self.c.setopt(self.c.CUSTOMREQUEST, "PUT")

        if self.debug:
            self.c.setopt(self.c.VERBOSE, 1)

        try:
            self.c.perform()
        except pycurl.error as e:
            self.response.body = str(e)
            self.response.status_code = -1
            return self.response

        _body = self.buffer.getvalue()
        self.response.status_code = self.c.getinfo(self.c.RESPONSE_CODE)
        if self.response.status_code == 200:
            _r = _body.decode('utf-8')
            # check for multiple json objects and convert to a list
            try:
                _resp = json.loads(_r)
            except:
                _r = '[' + _r.replace('}{', '},{') + ']'
            self.response.body = _r
        else:
            self.response.body = _body
        return self.response

    def post(self, url, data=None, files=None, headers=None, proxy=None, auth=None, cookies=None, verify=None):
        self.buffer = BytesIO()
        self.c.setopt(self.c.WRITEDATA, self.buffer)
        self.c.setopt(self.c.URL, url)
        self.set_cookies(cookies)
        self.set_proxy(proxy)
        self.set_verify(verify)
        self.set_auth(auth)
        self.c.setopt(self.c.POSTFIELDS, "")
        self.c.setopt(self.c.HTTPPOST, None)
        if headers:
            self.set_header(headers)
        else:
            self.c.setopt(self.c.HTTPHEADER, ['Content-Type: application/json', 'Accept: application/json'])

        if data:
            if type(data) is dict:
                _data = json.dumps(data)
            else:
                _data = data
            self.c.setopt(self.c.POSTFIELDS, _data)

        if files:
            list = []
            for key, value in files.items():
                if key == "file":
                    list.append(("file", (self.c.FORM_FILE, value)))
                else:
                    list.append((key, value))
                self.c.setopt(self.c.HTTPPOST, list)

        self.c.setopt(self.c.CUSTOMREQUEST, "POST")
        if self.debug:
            self.c.setopt(self.c.VERBOSE, 1)
        try:
            self.c.perform()
        except pycurl.error as e:
            self.response.body = str(e)
            self.response.status_code = -1
            return self.response

        _body = self.buffer.getvalue()
        self.response.status_code = self.c.getinfo(self.c.RESPONSE_CODE)
        if self.response.status_code == 200:
            _r = _body.decode('utf-8')
            # check for multiple json objects and convert to a list
            try:
                _resp = json.loads(_r)
            except:
                _r = '[' + _r.replace('}{', '},{') + ']'
            self.response.body = _r
        else:
            self.response.body = _body
        return self.response

    def set_header(self, headers):
        if headers:
            _headers = []
            if type(headers) is dict:
                for key, value in headers.items():
                    _headers.append(key + ':' + value)
            elif type(headers) is str:
                _headers.append(headers)
            else:
                for value in headers:
                    _headers.append(value)
            self.c.setopt(self.c.HTTPHEADER, _headers)

    def set_cookies(self, cookies):
        if cookies:
            self.c.setopt(self.c.COOKIELIST, '')
            if type(cookies) is dict:
                for key, value in cookies.items():
                    self.c.setopt(self.c.COOKIE, key + "=" + value)
            elif type(cookies) is str:
                self.c.setopt(self.c.COOKIE, cookies)
            else:
                for value in cookies:
                    self.c.setopt(self.c.COOKIE, value)

    def set_auth(self, auth):
        if auth:
            _u = None
            _p = None
            if type(auth) is tuple:
                _u, _p = auth
            elif type(auth) is list:
                _u = auth[0]
                _p = auth[1]
            elif type(auth) is dict:
                _u = auth["user"]
                _p = auth["pwd"]

            _auth = "{0}:{1}".format(_u, _p)
            self.c.setopt(self.c.USERPWD, _auth)

    def set_verify(self, verify):
        if verify:
            self.c.setopt(self.c.CAINFO, verify)
        else:
            self.c.setopt(self.c.SSL_VERIFYPEER, False)

    def set_proxy(self, proxy):
        # set proxy parameters
        if proxy:
            self.proxy_url = proxy['proxy_url']
            self.proxy_auth = "{0}:{1}".format(proxy["proxy_user"], proxy["proxy_pwd"])
            # set option for requests through proxy
            if self.proxy_url:
                self.c.setopt(self.c.PROXY, self.proxy_url)
                if self.proxy_auth:
                    self.c.setopt(self.c.PROXYUSERPWD, self.proxy_auth)
                    self.c.setopt(self.c.PROXYAUTH, 255)
        else:
            self.proxy_url = None
            self.proxy_auth = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.c.close()

    def close(self):
        self.c.close()
