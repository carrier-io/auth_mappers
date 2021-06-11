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
from ...auth_root.utils.decorators import require_kwargs


class HeaderMapper(RawMapper):
    @require_kwargs('info_endpoint')
    def __init__(self, *, mapper_settings: dict, access_denied_endpoint: str, **kwargs):
        super(HeaderMapper, self).__init__(**kwargs)
        self.access_denied_endpoint = access_denied_endpoint
        self.mapper_settings = mapper_settings

    def auth(self, response: Response, scope: str = '') -> Response:
        """ Map auth data """
        if scope not in self.mapper_settings:
            raise redirect(self.access_denied_endpoint)
        response = super(HeaderMapper, self).auth(response, scope)  # Set "raw" headers too
        auth_info = self.info(scope)
        if f"/{scope}" not in auth_info["auth_attributes"]["groups"]:
            raise NameError(f"User is not a memeber of {scope} group")
        try:
            for header, path in self.mapper_settings[scope].items():
                response.headers[header] = jsonpath_rw.parse(path).find(auth_info)[0].value
        except Exception as e:
            log.error(f"Failed to set scope headers: {str(e)}")
        return response
