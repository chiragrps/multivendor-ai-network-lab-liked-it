###
# DCN Network Tool — Read-Only Junos MCP Server
# Forked from Juniper/junos-mcp-server (Apache 2.0)
# 
# SAFETY: All write tools removed (load_and_commit_config, render_and_apply_j2_template, add_device)
# Only read-only operations: execute_junos_command, execute_junos_command_batch,
#   get_junos_config, junos_config_diff, gather_device_facts, get_router_list
#
# Original: https://github.com/Juniper/junos-mcp-server
# License: Apache 2.0 — Copyright (c) 1999-2025, Juniper Networks Inc.
###

from __future__ import annotations as _annotations

import argparse
import time
import re
from datetime import datetime, timezone
import logging
import os
import json
import sys
import signal
from pathlib import Path
from typing import Any, Dict, Generic
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount

from mcp.server.stdio import stdio_server
from mcp.server.session import ServerSession, ServerSessionT

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import LifespanResultT
from mcp.server.lowlevel.server import Server as MCPServer

from mcp.shared.context import LifespanContextT, RequestContext, RequestT
from mcp.types import (
    AnyFunction,
    ContentBlock,
    GetPromptResult,
    ToolAnnotations,
)

from jnpr.junos import Device
from jnpr.junos.exception import ConnectError

from utils.config import prepare_connection_params, validate_device_config, validate_all_devices

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger('jmcp-readonly')

# Global variable for devices (parsed from JSON file)
devices = {}

# Junos MCP Server
JUNOS_MCP = 'jmcp-readonly'

# ── BLOCKED COMMANDS (hardcoded safety — no config file needed) ──────────────
BLOCKED_COMMANDS = [
    r"request system reboot",
    r"request system halt",
    r"request system power-cycle",
    r"request system power-off",
    r"request system zeroize",
    r"request system software",
    r"request system firmware",
    r"request system snapshot",
    r"request system recover",
    r"configure",
    r"edit",
    r"set ",
    r"delete ",
    r"deactivate ",
    r"activate ",
    r"rollback",
    r"commit",
    r"load ",
]


class Context(BaseModel, Generic[ServerSessionT, LifespanContextT, RequestT]):
    """Context object providing access to MCP capabilities."""
    request_context: Any = None
    fastmcp: Any = None

    model_config = {"arbitrary_types_allowed": True}

    async def info(self, message: str) -> None:
        if self.request_context and hasattr(self.request_context, 'session'):
            try:
                await self.request_context.session.send_log_message(level="info", data=message)
            except Exception:
                log.info(message)
        else:
            log.info(message)

    async def debug(self, message: str) -> None:
        log.debug(message)

    async def warning(self, message: str) -> None:
        log.warning(message)

    async def error(self, message: str) -> None:
        log.error(message)


def _is_error_content(content_blocks: list[types.ContentBlock]) -> bool:
    """Check if content blocks indicate an error."""
    for block in content_blocks:
        if hasattr(block, 'text') and isinstance(block.text, str):
            if block.text.startswith("Error:") or block.text.startswith("Connection error"):
                return True
    return False


# ── COMMAND BLOCKLIST CHECK ──────────────────────────────────────────────────
def check_command_blocklist(command: str) -> tuple[bool, str | None]:
    """Block dangerous/write commands. Returns (is_blocked, message)."""
    if not command:
        return False, None
    normalized = " ".join(command.strip().split()).lower()
    for pattern in BLOCKED_COMMANDS:
        if re.match(pattern, normalized, re.IGNORECASE):
            return True, f"BLOCKED: Command '{command}' is not allowed (read-only mode). Only show/monitor commands are permitted."
    return False, None


# ── CORE: Run Junos CLI Command ─────────────────────────────────────────────
def _run_junos_cli_command(router_name: str, command: str, timeout: int = 360) -> str:
    """Internal helper to connect and run a Junos CLI command."""
    log.debug(f"Executing command {command} on router {router_name} with timeout {timeout}s")
    device_info = devices[router_name]
    try:
        connect_params = prepare_connection_params(device_info, router_name)
    except ValueError as ve:
        return f"Error: {ve}"
    try:
        with Device(**connect_params) as junos_device:
            junos_device.timeout = timeout
            op = junos_device.cli(command, warning=False)
            return op
    except ConnectError as ce:
        return f"Connection error to {router_name}: {ce}"
    except Exception as e:
        return f"An error occurred: {e}"


def get_timeout_with_fallback(arguments_timeout: int = None) -> int:
    """Get timeout value with fallback priority: arguments -> ENV -> default (360)"""
    if arguments_timeout is not None:
        return arguments_timeout
    env_timeout = os.getenv('JUNOS_TIMEOUT')
    if env_timeout is not None:
        try:
            return int(env_timeout)
        except ValueError:
            pass
    return 360


def get_stateless_with_fallback(default: bool = False) -> bool:
    """Get stateless mode from JMCP_STATELESS environment variable."""
    env_stateless = os.getenv('JMCP_STATELESS')
    if env_stateless is None:
        return default
    normalized_value = env_stateless.strip().lower()
    if normalized_value in {'1', 'true', 'yes', 'y', 'on'}:
        return True
    if normalized_value in {'0', 'false', 'no', 'n', 'off'}:
        return False
    return default


# ══════════════════════════════════════════════════════════════════════════════
# READ-ONLY TOOL HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

async def handle_execute_junos_command(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for execute_junos_command tool (read-only: blocks write commands)"""
    start_time = time.time()
    start_timestamp = datetime.now(timezone.utc).isoformat()
    router_name = arguments.get("router_name", "")
    command = arguments.get("command", "")
    timeout = get_timeout_with_fallback(arguments.get("timeout"))

    is_blocked, blocked_message = check_command_blocklist(command)
    if is_blocked:
        result = blocked_message
    elif router_name not in devices:
        result = f"Router {router_name} not found in the device mapping."
    else:
        log.debug(f"Executing command {command} on router {router_name} with timeout {timeout}s")
        result = _run_junos_cli_command(router_name, command, timeout)

    end_time = time.time()
    end_timestamp = datetime.now(timezone.utc).isoformat()
    execution_duration = round(end_time - start_time, 3)
    content_block = types.TextContent(
        type="text",
        text=result,
        annotations={"router_name": router_name,
                     "command": command,
                     "metadata": {
                        "execution_duration": execution_duration,
                        "start_time": start_timestamp,
                        "end_time": end_timestamp
                        }
                    })
    return [content_block]


async def handle_execute_junos_command_batch(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for execute_junos_command_batch tool — parallel execution on multiple routers (read-only)."""
    import asyncio

    batch_start_time = time.time()
    router_names = arguments.get("router_names", [])
    command = arguments.get("command", "")
    timeout = get_timeout_with_fallback(arguments.get("timeout"))

    if not router_names:
        return [types.TextContent(type="text", text="Error: router_names list is required and cannot be empty")]
    if not command:
        return [types.TextContent(type="text", text="Error: command is required")]

    is_blocked, blocked_message = check_command_blocklist(command)
    if is_blocked:
        return [types.TextContent(type="text", text=blocked_message)]

    invalid_routers = [r for r in router_names if r not in devices]
    if invalid_routers:
        return [types.TextContent(type="text", text=f"Error: The following routers not found in device mapping: {', '.join(invalid_routers)}")]

    log.info(f"Executing batch command on {len(router_names)} routers in parallel: {command}")
    await context.info(f"Executing command on {len(router_names)} routers in parallel...")

    async def execute_on_router(router_name: str) -> dict:
        start_time = time.time()
        start_timestamp = datetime.now(timezone.utc).isoformat()
        try:
            result = await anyio.to_thread.run_sync(
                _run_junos_cli_command, router_name, command, timeout
            )
            is_error = result.startswith("Connection error") or result.startswith("An error occurred") or result.startswith("Error:")
            status = "failed" if is_error else "success"
        except Exception as e:
            result = f"Exception during execution: {str(e)}"
            status = "failed"

        end_time = time.time()
        return {
            "router_name": router_name,
            "status": status,
            "output": result,
            "execution_duration": round(end_time - start_time, 3),
            "start_time": start_timestamp,
            "end_time": datetime.now(timezone.utc).isoformat()
        }

    results = await asyncio.gather(
        *[execute_on_router(rn) for rn in router_names],
        return_exceptions=False
    )

    batch_duration = round(time.time() - batch_start_time, 3)
    successful_count = sum(1 for r in results if r["status"] == "success")
    failed_count = len(results) - successful_count

    response_data = {
        "summary": {
            "command": command,
            "total_routers": len(router_names),
            "successful": successful_count,
            "failed": failed_count,
            "total_duration": batch_duration
        },
        "results": results
    }

    formatted_output = json.dumps(response_data, indent=2)
    log.info(f"Batch execution: {successful_count} ok, {failed_count} failed, {batch_duration}s")

    return [types.TextContent(
        type="text",
        text=formatted_output,
        annotations={"command": command, "router_names": router_names,
                     "batch_metadata": {"total_routers": len(router_names),
                                        "successful": successful_count,
                                        "failed": failed_count,
                                        "total_duration": batch_duration}}
    )]


async def handle_get_junos_config(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for get_junos_config tool (read-only)"""
    router_name = arguments.get("router_name", "")
    if router_name not in devices:
        result = f"Router {router_name} not found in the device mapping."
    else:
        log.debug(f"Getting configuration from router {router_name}")
        result = _run_junos_cli_command(router_name, "show configuration | display inheritance no-comments | display set | no-more")
    return [types.TextContent(type="text", text=result, annotations={"router_name": router_name})]


async def handle_junos_config_diff(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for junos_config_diff tool (read-only: compare rollback versions)"""
    router_name = arguments.get("router_name", "")
    version = arguments.get("version", 1)
    if router_name not in devices:
        result = f"Router {router_name} not found in the device mapping."
    else:
        log.debug(f"Getting configuration diff from router {router_name} for version {version}")
        result = _run_junos_cli_command(router_name, f"show configuration | compare rollback {version}")
    return [types.TextContent(type="text", text=result, annotations={"router_name": router_name, "config_diff_version": version})]


async def handle_gather_device_facts(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for gather_device_facts tool (read-only)"""
    router_name = arguments.get("router_name", "")
    timeout = get_timeout_with_fallback(arguments.get("timeout"))

    if router_name not in devices:
        result = f"Router {router_name} not found in the device mapping."
    else:
        log.debug(f"Getting facts from router {router_name} with timeout {timeout}s")
        device_info = devices[router_name]
        try:
            connect_params = prepare_connection_params(device_info, router_name)
            connect_params['timeout'] = timeout
        except ValueError as ve:
            result = f"Error: {ve}"
        else:
            try:
                with Device(**connect_params) as junos_device:
                    facts = junos_device.facts
                    facts_dict = dict(facts)

                    def json_serializer(obj):
                        if hasattr(obj, '_asdict'):
                            return obj._asdict()
                        elif hasattr(obj, '__dict__'):
                            return obj.__dict__
                        else:
                            return str(obj)

                    result = json.dumps(facts_dict, indent=2, default=json_serializer)
            except ConnectError as ce:
                result = f"Connection error to {router_name}: {ce}"
            except Exception as e:
                result = f"An error occurred: {e}"

    return [types.TextContent(type="text", text=result, annotations={"router_name": router_name})]


async def handle_get_router_list(arguments: dict, context: Context) -> list[types.ContentBlock]:
    """Handler for get_router_list tool (read-only)"""
    import copy
    log.debug("Getting list of routers")
    router_info = {}
    for router_name, device_config in devices.items():
        filtered_config = copy.deepcopy(device_config)
        if "ssh_config" in filtered_config:
            del filtered_config["ssh_config"]
        if "auth" in filtered_config:
            if "password" in filtered_config["auth"]:
                del filtered_config["auth"]["password"]
            if "private_key_path" in filtered_config["auth"]:
                del filtered_config["auth"]["private_key_path"]
        router_info[router_name] = filtered_config
    result = json.dumps(router_info, indent=2)
    return [types.TextContent(type="text", text=result)]


# ══════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY — READ-ONLY TOOLS ONLY
# ══════════════════════════════════════════════════════════════════════════════
# REMOVED: load_and_commit_config, render_and_apply_j2_template, add_device, reload_devices
TOOL_HANDLERS = {
    "execute_junos_command": handle_execute_junos_command,
    "execute_junos_command_batch": handle_execute_junos_command_batch,
    "get_junos_config": handle_get_junos_config,
    "junos_config_diff": handle_junos_config_diff,
    "gather_device_facts": handle_gather_device_facts,
    "get_router_list": handle_get_router_list,
}


def create_mcp_server() -> Server:
    """Create and configure the MCP server with read-only tools only."""
    app = Server(JUNOS_MCP, version="1.0.0")

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        handler = TOOL_HANDLERS.get(name)
        if handler:
            try:
                request_context = app.request_context
            except LookupError:
                request_context = None
            context = Context(request_context=request_context, fastmcp=app)
            content_blocks = await handler(arguments, context=context)
            return types.CallToolResult(content=content_blocks, isError=_is_error_content(content_blocks))
        content_blocks = [types.TextContent(type="text", text=f"Unknown tool: {name}")]
        return types.CallToolResult(content=content_blocks, isError=True)

    @app.list_resources()
    async def list_resources() -> list[types.Resource]:
        return []

    @app.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return []

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        """List available tools — READ-ONLY ONLY"""
        return [
            types.Tool(
                name="execute_junos_command",
                description="Execute a read-only Junos CLI command (show/monitor only — write commands are blocked)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "router_name": {"type": "string", "description": "The name of the router"},
                        "command": {"type": "string", "description": "The CLI command to execute (show/monitor commands only)"},
                        "timeout": {"type": "integer", "description": "Command timeout in seconds", "default": 360}
                    },
                    "required": ["router_name", "command"]
                }
            ),
            types.Tool(
                name="execute_junos_command_batch",
                description="Execute the same read-only Junos command on multiple routers in parallel. Returns structured JSON with per-router results.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "router_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of router names to execute the command on"
                        },
                        "command": {"type": "string", "description": "The command to execute on all routers (show/monitor only)"},
                        "timeout": {"type": "integer", "description": "Command timeout in seconds per router", "default": 360}
                    },
                    "required": ["router_names", "command"]
                }
            ),
            types.Tool(
                name="get_junos_config",
                description="Get the running configuration of a Junos router (display set format)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "router_name": {"type": "string", "description": "The name of the router"}
                    },
                    "required": ["router_name"]
                }
            ),
            types.Tool(
                name="junos_config_diff",
                description="Get the configuration diff against a rollback version",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "router_name": {"type": "string", "description": "The name of the router"},
                        "version": {"type": "integer", "description": "Rollback version to compare against (1-49)", "default": 1}
                    },
                    "required": ["router_name"]
                }
            ),
            types.Tool(
                name="gather_device_facts",
                description="Gather Junos device facts (model, version, serial, uptime, etc.)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "router_name": {"type": "string", "description": "The name of the router"},
                        "timeout": {"type": "integer", "description": "Connection timeout in seconds", "default": 360}
                    },
                    "required": ["router_name"]
                }
            ),
            types.Tool(
                name="get_router_list",
                description="Get list of all available Junos routers with their IP and auth type",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
        ]

    return app


def main():
    parser = argparse.ArgumentParser(description="DCN Junos MCP Server (Read-Only)")
    parser.add_argument('-f', '--device-mapping', default="/app/config/devices.json", type=str,
                        help='JSON file containing the device mapping')
    parser.add_argument('-H', '--host', default="0.0.0.0", type=str, help='Server host')
    parser.add_argument('-t', '--transport', default="streamable-http", type=str, help='Transport: streamable-http or stdio')
    parser.add_argument('-p', '--port', default=30030, type=int, help='Server port')

    args = parser.parse_args()
    global devices

    try:
        with open(args.device_mapping, 'r') as f:
            devices = json.load(f)
            validate_all_devices(devices)
            log.info(f"Loaded and validated {len(devices)} device(s) — READ-ONLY mode")
    except FileNotFoundError:
        log.warning(f"Device file {args.device_mapping} not found — starting with empty inventory")
        devices = {}
    except json.JSONDecodeError:
        log.error(f"File {args.device_mapping} is not valid JSON")
        devices = {}
    except ValueError as e:
        log.error(f"Device config validation failed: {e}")
        sys.exit(1)

    def signal_handler(sig, frame):
        print("\nShutting down JMCP read-only server...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    mcp_server = create_mcp_server()

    try:
        if args.transport == 'stdio':
            async def run_stdio():
                async with stdio_server() as (read_stream, write_stream):
                    await mcp_server.run(read_stream, write_stream, mcp_server.create_initialization_options())
            anyio.run(run_stdio)

        elif args.transport == 'streamable-http':
            async def run_streamable_http():
                stateless_mode = get_stateless_with_fallback(default=True)
                session_manager = StreamableHTTPSessionManager(
                    app=mcp_server, event_store=None, stateless=stateless_mode
                )
                log.info(f"Streamable HTTP: {'stateless' if stateless_mode else 'stateful'}")

                async def handle_streamable_http(scope, receive, send):
                    await session_manager.handle_request(scope, receive, send)

                async def lifespan(app):
                    async with session_manager.run():
                        log.info(f"JMCP Read-Only server on http://{args.host}:{args.port}/mcp")
                        log.info(f"Tools: {', '.join(TOOL_HANDLERS.keys())}")
                        log.info(f"Devices: {len(devices)}")
                        yield
                        log.info("Server shutting down...")

                starlette_app = Starlette(
                    routes=[Mount("/mcp", app=handle_streamable_http)],
                    lifespan=lifespan
                )

                import uvicorn
                config = uvicorn.Config(starlette_app, host=args.host, port=args.port, log_level="info")
                server = uvicorn.Server(config)
                await server.serve()

            anyio.run(run_streamable_http)
        else:
            log.error(f"Unsupported transport: {args.transport}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)


if __name__ == '__main__':
    main()
