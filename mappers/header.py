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

import jsonpath_rw

from flask import redirect, Response
from pylon.core.tools import log

from .raw import RawMapper


class HeaderMapper(RawMapper):
    def __init__(self, *, info_endpoint: str, mapper_settings: dict, access_denied_endpoint: str, **kwargs):
        super().__init__(**kwargs, info_endpoint=info_endpoint)
        self.access_denied_endpoint = access_denied_endpoint
        self.mapper_settings = mapper_settings
        #
        self.check_header_scope_group = self.mapper_settings.pop("check_header_scope_group", True)

    def auth(self, response: Response, scope: str = '') -> Response:
        """ Map auth data """
        if scope not in self.mapper_settings:
            raise redirect(self.access_denied_endpoint)
        response = super(HeaderMapper, self).auth(response, scope)  # Set "raw" headers too
        auth_info = self.info(scope)
        if self.check_header_scope_group and \
                f"/{scope}" not in auth_info["auth_attributes"]["groups"]:
            raise NameError(f"User is not a memeber of {scope} group")
        try:
            for header, path in self.mapper_settings[scope].items():
                response.headers[header] = jsonpath_rw.parse(path).find(auth_info)[0].value
        except Exception as e:
            log.error(f"Failed to set scope headers: {str(e)}")
        return response
