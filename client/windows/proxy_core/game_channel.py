"""Battle-priority routing over a dedicated encrypted SSH transport."""
from copy import deepcopy

GAME_HOST = 'game.granbluefantasy.jp'
GAME_ENDPOINT_IP = '203.104.' + '248.14'
GAME_HOSTS = (GAME_HOST, 'ws.game.granbluefantasy.jp', GAME_ENDPOINT_IP)
REALTIME_HOSTS = ('ws.game.granbluefantasy.jp', GAME_ENDPOINT_IP)


def is_battle_target(host, port):
    """Match only GBF HTTPS origins and its observed realtime service port."""
    host = host.lower().removesuffix('.')
    return port == 443 and host in GAME_HOSTS or port == 11240 and host in REALTIME_HOSTS


def game_channel_config(config):
    if 'game_channel' not in config:
        return None
    channel = config['game_channel']
    if not isinstance(channel, dict) or type(channel.get('enabled')) is not bool:
        raise ValueError('game_channel.enabled must be boolean')
    port = channel.get('socks_port', 18125)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('game_channel.socks_port must be an integer from 1 to 65535')
    ssh = config.get('ssh')
    if port == config.get('port') or isinstance(ssh, dict) and port == ssh.get('socks_port'):
        raise ValueError('Game SOCKS port must differ from shared SOCKS and proxy ports')
    if not channel['enabled']:
        return None
    if not isinstance(ssh, dict) or not ssh:
        raise ValueError('game_channel requires SSH configuration')
    # Unknown game_channel fields can never override host, identity, or SSH policy.
    result = deepcopy(ssh)
    result['socks_port'] = port
    return result
