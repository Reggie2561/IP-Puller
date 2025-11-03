"""Ping an IP address and return raw RTT values for each ping."""
import time
import requests
from typing import Literal

PingCheckResults = dict[str, list[
    list[list[str | float]] | list[None | dict[Literal['message'], str]]
]]

CHECK_HOST_API = 'https://check-host.net'


def ping(target_ip: str) -> str:
    """Send a ping to the target IP and return raw RTT values per node."""
    s = requests.Session()

    def send_ping_request(ip: str) -> tuple[str | None, dict[str, object] | None]:
        response = s.get(f'{CHECK_HOST_API}/check-ping?host={ip}', headers={'Accept': 'application/json'})
        response.raise_for_status()

        nodes = response.json()
        if not isinstance(nodes, dict):
            raise TypeError(f'Expected "dict", got "{type(nodes).__name__}"')
        request_id = nodes.get('request_id')
        if request_id is None:
            return None, None
        if not isinstance(request_id, str):
            raise TypeError(f'Expected "str", got "{type(request_id).__name__}"')
        return request_id, nodes

    def get_ping_results(request_id: str, delay: int = 10) -> PingCheckResults:
        for i in range(delay, 0, -1):
            time.sleep(1)
        print(' ' * 50, end='\r')

        response = s.get(f'{CHECK_HOST_API}/check-result/{request_id}', headers={'Accept': 'application/json'})
        response.raise_for_status()

        results: PingCheckResults = response.json()
        if not isinstance(results, dict):
            raise TypeError(f'Expected "dict", got "{type(results).__name__}"')
        return results

    request_id, nodes = send_ping_request(target_ip)
    if not request_id:
        raise RuntimeError("Failed to get request ID from API response")

    results: PingCheckResults = get_ping_results(request_id)
    if not results:
        raise RuntimeError("Failed to retrieve ping results")

    ping_results = ""
    for node, pings in results.items():
        country = nodes['nodes'][node][1]
        city = nodes['nodes'][node][2]
        if not isinstance(country, str) or not isinstance(city, str):
            raise TypeError("Invalid country or city type")

        message = None
        if pings is None:
            message = 'timeout'
        elif pings[0] is None:
            message = pings[1]['message']

        this_rtt_values: list[str | float] = []
        successful_pings = 0

        if message is None:
            for ping_entry in pings:
                for i in range(4):
                    result = ping_entry[i][0]
                    rtt = ping_entry[i][1]
                    if result == 'OK':
                        successful_pings += 1
                        this_rtt_values.append(round(rtt * 1000, 1))
                    else:
                        this_rtt_values.append('timeout')

        if this_rtt_values:
            rtts_formatted = ' ms | '.join(str(v) for v in this_rtt_values)
            ping_results += f"{"="*50}\n{country:5} {city:5} {successful_pings}/4\n{rtts_formatted} ms\n"
        else:
            ping_results += f"{"="*50}\n{country} {city} 0/4\n{message or 'timeout'}\n"

    return ping_results
