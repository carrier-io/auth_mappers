#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
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

import json

import flask  # pylint: disable=E0401
import jsonpath_rw  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0401
from pylon.core.tools import module  # pylint: disable=E0401

from plugins.auth_core.tools import rpc_tools  # pylint: disable=E0401


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # RPCs
        self._rpcs = [
            [self._noop_info_mapper, "auth_noop_info_mapper"],
            #
            [self._json_success_mapper, "auth_json_success_mapper"],
            [self._json_info_mapper, "auth_json_info_mapper"],
            #
            [self._header_success_mapper, "auth_header_success_mapper"],
        ]

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.register_function(*rpc_item)
        # Register test info mapper
        self.context.rpc_manager.call.auth_register_info_mapper(
            None, "auth_noop_info_mapper"
        )
        # Register JSON mappers
        self.context.rpc_manager.call.auth_register_success_mapper(
            "json", "auth_json_success_mapper"
        )
        self.context.rpc_manager.call.auth_register_info_mapper(
            "json", "auth_json_info_mapper"
        )
        # Register header mapper
        self.context.rpc_manager.call.auth_register_success_mapper(
            "header", "auth_header_success_mapper"
        )

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module")
        # Unregister header mapper
        self.context.rpc_manager.call.auth_unregister_success_mapper("header")
        # Unregister JSON mappers
        self.context.rpc_manager.call.auth_unregister_info_mapper("json")
        self.context.rpc_manager.call.auth_unregister_success_mapper("json")
        # Unregister test info mapper
        self.context.rpc_manager.call.auth_unregister_info_mapper(None)
        # De-init RPCs
        for rpc_item in self._rpcs:
            self.context.rpc_manager.unregister_function(*rpc_item)

    #
    # RPC
    #

    #
    # RPC: No-op info mapper
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _noop_info_mapper(self, auth_ctx, scope):  # pylint: disable=R0201,W0613
        mimetype = "application/json"
        data = json.dumps(auth_ctx, default=str)
        #
        return mimetype, data

    #
    # RPC: json mappers
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _json_success_mapper(self, source, auth_type, auth_id, auth_reference):  # pylint: disable=W0613
        mapper_config = self.descriptor.config.get("json", dict())
        endpoint = mapper_config.get("endpoint", None)
        #
        if endpoint is None:
            with self.context.app.app_context():
                endpoint = flask.url_for(
                    "auth_core.info",
                    target=source["target"],
                    scope=source["scope"],
                )
        #
        headers = dict()
        #
        headers["X-Auth-Session-Endpoint"] = endpoint
        headers["X-Auth-Session-Name"] = \
            self.context.rpc_manager.call.auth_get_session_cookie_name()
        headers["X-Auth-Session-Id"] = auth_reference
        #
        return True, headers

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _json_info_mapper(self, auth_ctx, scope):
        mapper_config = self.descriptor.config.get("json", dict())
        scopes_config = mapper_config.get("scopes", dict())
        scope_config = scopes_config.get(scope, dict())
        #
        #
        result = {"raw": auth_ctx}
        for key, path in scope_config.items():
            try:
                result[key] = jsonpath_rw.parse(path).find(auth_ctx)[0].value
            except:  # pylint: disable=W0702
                log.exception("Failed to set scope data: %s -> %s", key, path)
        #
        mimetype = "application/json"
        data = json.dumps(result, default=str)
        #
        return mimetype, data

    #
    # RPC: header mapper
    #

    @rpc_tools.wrap_exceptions(RuntimeError)
    def _header_success_mapper(self, source, auth_type, auth_id, auth_reference):
        auth_ctx = \
            self.context.rpc_manager.call.auth_get_referenced_auth_context(
                auth_reference
            )
        #
        mapper_config = self.descriptor.config.get("header", dict())
        scopes_config = mapper_config.get("scopes", dict())
        scope_config = scopes_config.get(source["scope"], dict())
        scope_require = scope_config.get("require", list())
        #
        headers = dict()
        #
        for requirement in scope_require:
            if not self._have_requirement(
                auth_type, auth_id,
                requirement.get("scope", 1),
                requirement.get("permissions", list()),
            ):
                return False, headers
        #
        for key, path in scope_config.get("headers", dict()).items():
            try:
                headers[key] = jsonpath_rw.parse(path).find(auth_ctx)[0].value
            except:  # pylint: disable=W0702
                log.exception("Failed to set scope data: %s -> %s", key, path)
        #
        return True, headers

    def _have_requirement(self, auth_type, auth_id, req_scope, req_permissions):
        try:
            auth_id = int(auth_id)
        except:  # pylint: disable=W0702
            auth_id = "-"
        #
        if auth_type == "user":
            auth_permissions = \
                self.context.rpc_manager.call.auth_get_user_permissions(
                    auth_id, req_scope
                )
        elif auth_type == "token":
            auth_permissions = \
                self.context.rpc_manager.call.auth_get_token_permissions(
                    auth_id, req_scope
                )
        else:
            auth_permissions = list()
        #
        req_permissions = set(req_permissions)
        auth_permissions = set(auth_permissions)
        #
        return req_permissions.issubset(auth_permissions)
