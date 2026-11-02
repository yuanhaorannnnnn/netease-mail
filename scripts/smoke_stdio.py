"""Credential-free stdio smoke test; run with the installed runtime Python."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    root = Path(__file__).resolve().parent.parent
    # An unsupported synthetic domain fails before keyring access, without changing HOME.
    env = dict(os.environ, NETEASE_EMAIL='offline-smoke@example.org')
    params = StdioServerParameters(command='sh', args=[str(root / 'scripts/run-server.sh')], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            assert 'get_server_info' in names and 'search_emails' in names
            result = await session.call_tool('get_server_info', {})
            assert not result.isError
            info = json.loads(result.content[0].text)
            expected = hashlib.sha256((root / 'skills/netease-mail/scripts/server.py').read_bytes()).hexdigest()
            assert info['source_sha256'] == expected
            invalid = await session.call_tool('list_folders', {})
            assert invalid.isError and 'supported 163.com' in str(invalid.content)
            print(json.dumps({'initialize': 'pass', 'tools_count':len(names), 'source_sha256':expected, 'invalid_account':'rejected', 'credentials_read':False, 'mailbox_access':False}))

if __name__ == '__main__':
    asyncio.run(main())
