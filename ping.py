"""Ping an IP address.
"""
import statistics
import time
from typing import Literal
import requests

PingCheckResults = dict[str, list[
    list[list[str | float]] | list[None | dict[Literal['message'], str]]
]]

CHECK_HOST_API = 'https://check-host.net'


def ping(target_ip: str) -> None:
    s = requests.Session()
    """Continuously pings the target IP until the user closes the script."""

    def send_ping_request(ip: str) -> tuple[str | None, dict[str, object] | None]:
        """Send a ping request to the Check-Host API."""
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
        """Fetch the results using the request ID."""
        for i in range(delay, 0, -1):
            print(f'Waiting {i} second{pluralize(i)} for ping request to complete...', end='\r')
            time.sleep(1)
        print(' ' * 50, end='\r')

        response = s.get(f'{CHECK_HOST_API}/check-result/{request_id}', headers={'Accept': 'application/json'})
        response.raise_for_status()

        results: PingCheckResults = response.json()
        if not isinstance(results, dict):
            raise TypeError(f'Expected "dict", got "{type(results).__name__}"')

        for pings in results.values():
            if pings is None:
                continue
            if not isinstance(pings, list):
                raise TypeError(f'Expected "list", got "{type(pings).__name__}"')

        return results

    def pluralize(variable: int) -> str:
        return 's' if variable > 1 else ''

    for i in range(0, 1):
        request_id, nodes = send_ping_request(target_ip)
        results: PingCheckResults = get_ping_results(request_id)
        if not isinstance(results, dict):
            raise TypeError(f'Expected "dict", got "{type(results).__name__}"')
        if not results:
            print('Failed to retrieve ping results.')
            time.sleep(10)
            continue

        print(f"\nPing Results from {target_ip}")
        print('-' * 80)
        print(f"{'Country':20} {'City':20} {'Success':10} {'Min RTT (ms)':15} {'Avg RTT (ms)':15} {'Max RTT (ms)':15}")
        ping_results = ""
        for node, pings in results.items():
            country = nodes['nodes'][node][1]
            if not isinstance(country, str):
                raise TypeError(f'Expected "str", got "{type(country).__name__}"')
            city = nodes['nodes'][node][2]
            if not isinstance(city, str):
                raise TypeError(f'Expected "str", got "{type(city).__name__}"')

            message = None
            if pings is None:
                message = 'timeout'
            elif pings[0] is None:
                message = pings[1]['message']

            this_rtt_values: list[float | int] = []
            successful_pings = 0

            if message is None:
                for ping in pings:
                    for i in range(4):
                        result = ping[i][0]
                        if not isinstance(result, str):
                            raise TypeError(f'Expected "str", got "{type(result).__name__}"')
                        rtt = ping[i][1]
                        if not isinstance(rtt, (float, int)):
                            raise TypeError(f'Expected "(float, int)", got "{type(rtt).__name__}"')

                        if result == 'OK':
                            successful_pings += 1
                        this_rtt_values.append(rtt)

            if this_rtt_values:
                rtt_min = min(this_rtt_values) * 1000
                rtt_avg = statistics.mean(this_rtt_values) * 1000
                rtt_max = max(this_rtt_values) * 1000
                ping_results += f"{country:20} {city:20} {successful_pings}/4       {round(rtt_min,1):15}min ms {round(rtt_avg,1):15}avg ms {round(rtt_max,1):15}max ms\n"
            else:
                ping_results += f"{country:20} {city:20} 0/4         {message:15} {message:15} {message:15}\n"
        return ping_results

