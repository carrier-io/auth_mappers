#   Copyright 2021 getcarrier.io
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

""" Module """
import flask  # pylint: disable=E0401
import jinja2  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401

from .mappers.header import HeaderMapper
from .mappers.json import JsonMapper
from .mappers.raw import RawMapper


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        #
        self.settings = self.descriptor.config
        self.rpc_prefix = None
        self.info_prefix = None

    def init(self):
        """ Init module """
        log.info('Initializing module auth_mappers')
        root_settings = self.context.module_manager.modules["auth_root"].config
        self.rpc_prefix = root_settings['rpc_manager']['prefix']['mappers']
        self.info_prefix = root_settings['rpc_manager']['prefix']['info']

        mappers = dict()
        mappers['raw'] = RawMapper(info_endpoint=self.settings['endpoints']['info'])
        mappers['header'] = HeaderMapper(
            info_endpoint=self.settings['endpoints']['info'],
            mapper_settings=self.settings['header'],
            access_denied_endpoint=root_settings['endpoints']['access_denied']
        )
        mappers['json'] = JsonMapper(
            info_endpoint=self.settings['endpoints']['info'],
            mapper_settings=self.settings['json'],
            access_denied_endpoint=root_settings['endpoints']['access_denied']
        )
        # rpc_manager
        for mapper_name, mapper_instance in mappers.items():
            self.context.rpc_manager.register_function(
                func=mapper_instance.auth,
                name=f'{self.rpc_prefix}{mapper_name}'
            )
            log.debug(f'Auth mapper {str(mapper_name)} registered in rpc_manager under name {self.rpc_prefix}{mapper_name}')
        # Info RPCs
        for mapper_name, mapper_instance in mappers.items():
            self.context.rpc_manager.register_function(
                func=mapper_instance.info,
                name=f'{self.info_prefix}{mapper_name}'
            )
            log.debug(f'Auth info provider {str(mapper_name)} registered in rpc_manager under name {self.info_prefix}{mapper_name}')

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info('De-initializing module auth_mappers')
