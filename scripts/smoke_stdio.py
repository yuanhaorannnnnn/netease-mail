"""Credential-free stdio smoke test; run with the installed runtime Python."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    root = Path(__file__).resolve().parent.parent
    # Preserve the installed runtime before isolating account configuration via HOME.
    data_home = os.environ.get('XDG_DATA_HOME') or str(Path.home() / '.local/share')
    with tempfile.TemporaryDirectory(prefix='netease-empty-home-') as home:
        env = dict(os.environ, HOME=home, NETEASE_EMAIL='', XDG_CONFIG_HOME=home,
                   XDG_DATA_HOME=data_home)
        env.pop('DBUS_SESSION_BUS_ADDRESS', None)
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
                missing = await session.call_tool('list_folders', {})
                assert missing.isError and 'not configured' in str(missing.content)
                print(json.dumps({'initialize': 'pass', 'tools_count':len(names), 'source_sha256':expected, 'unconfigured_account':'rejected', 'mailbox_access':False}))

if __name__ == '__main__':
    asyncio.run(main())
