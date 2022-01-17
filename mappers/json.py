#   Copyright 2020
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import urllib
import jsonpath_rw
import flask
from flask import request, session, redirect, Response

from pylon.core.tools import log

from .raw import RawMapper


class JsonMapper(RawMapper):
    def __init__(self, *, info_endpoint: str, mapper_settings: dict, access_denied_endpoint: str, **kwargs):
        super(JsonMapper, self).__init__(**kwargs, info_endpoint=info_endpoint)
        self.info_endpoint = info_endpoint
        self.mapper_settings = mapper_settings
        self.access_denied_endpoint = access_denied_endpoint

    def auth(self, response: Response, scope: str = '') -> Response:
        """ Map auth data """
        response.headers["X-Auth-Session-Endpoint"] = flask.url_for(
            "auth_root.info",
            target="json",
            scope=urllib.parse.quote_plus(scope),
        )
        response.headers["X-Auth-Session-Name"] = session["name"]
        response.headers["X-Auth-Session-Id"] = session["auth_cookie"]
        return response

    def info(self, scope: str = '') -> dict:
        """ Map info data """
        if scope not in self.mapper_settings:
            raise redirect(self.access_denied_endpoint)
        auth_info = super(JsonMapper, self).info(scope)
        result = {"raw": auth_info}
        try:
            for key, path in self.mapper_settings[scope].items():
                result[key] = jsonpath_rw.parse(path).find(auth_info)[0].value
        except:  # pylint: disable=W0702
            from traceback import format_exc
            log.error(f"Failed to set scope data {format_exc()}")
        return result
