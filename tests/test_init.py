import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from aiodhcpwatcher import DHCPRequest, start

logging.basicConfig(level=logging.DEBUG)


class MockSocket:

    def __init__(self, reader: int) -> None:
        self._fileno = reader
        self.close = MagicMock()
        self.buffer = b""

    def recv(self) -> bytes:
        buffer = self.buffer
        self.buffer = b""
        return buffer

    def fileno(self) -> int:
        return self._fileno


@pytest.mark.asyncio
async def test_start_stop():
    """Test start and stop."""

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        pass

    stop = start(_handle_dhcp_packet)
    stop()


@pytest.mark.asyncio
async def test_watcher():
    """Test mocking a dhcp packet to the watcher."""

    def _handle_dhcp_packet(data: DHCPRequest) -> None:
        pass

    r, w = os.pipe()

    mock_socket = MockSocket(r)
    with patch(
        "aiodhcpwatcher.AIODHCPWatcher._make_listen_socket", return_value=mock_socket
    ), patch("aiodhcpwatcher.AIODHCPWatcher._verify_working_pcap"):
        stop = start(_handle_dhcp_packet)
        os.write(w, b"test")
        stop()
