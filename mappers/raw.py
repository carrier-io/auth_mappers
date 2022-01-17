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

from flask import request, session, Response

from .base import BaseMapper


class RawMapper(BaseMapper):
    def __init__(self, *, info_endpoint: str, **kwargs):
        super(RawMapper, self).__init__(**kwargs)
        self.info_endpoint = info_endpoint

    def auth(self, response: Response, scope: str = '') -> Response:
        """ Map auth data """
        response.headers["X-Auth-Session-Endpoint"] = f"{request.base_url}{self.info_endpoint}/query"
        response.headers["X-Auth-Session-Name"] = session["name"]
        response.headers["X-Auth-Session-Id"] = session["auth_cookie"]
        return response

    def info(self, scope: str = ''):
        """ Map info data """
        result = {
            "auth": session.get("auth", False),
            "auth_errors": session.get("auth_errors", []),
            "auth_nameid": session.get("auth_nameid", ""),
            "auth_sessionindex": session.get("auth_sessionindex", ""),
            "auth_attributes": session.get("auth_attributes", {})
        }
        return result
