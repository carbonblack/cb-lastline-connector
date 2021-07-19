import os
import re
import socket
import sys
import tempfile
import threading
import unittest
from time import sleep

import requests_mock
from cbint.utils.detonation import BinaryDatabaseController
from cbint.utils.detonation.binary_analysis import DeepAnalysisThread, CbAPIProducerThread

from cbopensource.connectors.lastline.bridge import LastlineConnector

try:
    from .utils.mock_server import MockLastlineServer
except ImportError:
    from utils.mock_server import MockLastlineServer

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

test_dir = os.path.dirname(os.path.abspath(__file__))


class ServerNeverWokeUpError(Exception):
    pass


def sleep_till_available(conn_tuple):
    num_retries = 5
    while num_retries:
        s = socket.socket()
        try:
            s.connect(conn_tuple)
        except socket.error:
            num_retries -= 1
            sleep(.1)
        else:
            return

    raise ServerNeverWokeUpError(conn_tuple)

@unittest.skip("Not working without debugger on")
class LastlineTest(unittest.TestCase):
    match_binary_summary = re.compile(r"/api/v1/binary/([A-Fa-f0-9]{32})/summary")
    match_binary_download = re.compile(r"/api/v1/binary/([A-Fa-f0-9]{32})$")
    match_binary_search = re.compile(r"/api/v1/binary")
    match_storage_events = re.compile(r"/api/v1/storage/events/partition")
    match_lastline_analysis = re.compile(r"/analysis/submit/file.json")
    match_lastline_analysis_task_get_result = re.compile(r"/analysis/get.json")

    def run(self, result=None):
        with requests_mock.Mocker() as mocker:
            mock_server = MockLastlineServer()
            mocker.get("/api/info", json=mock_server.handle_api_info)
            mocker.get(self.match_binary_download, content=mock_server.handle_get_binary)
            mocker.get(self.match_binary_summary, json=mock_server.handle_binary_summary)
            mocker.get(self.match_binary_search,
                       json=mock_server.handle_binary_search)
            mocker.get(self.match_storage_events, json=mock_server.handle_storage_events)
            mocker.post(self.match_lastline_analysis, json=mock_server.handle_lastline_analysis_submission)
            mocker.post(self.match_lastline_analysis_task_get_result,
                        json=mock_server.handle_lastline_analysis_task_get_result)
            super(LastlineTest, self).run(result)

    def setUp(self):
        self.temp_directory = tempfile.mkdtemp()

        path_to_tests = os.path.dirname(os.path.realpath(__file__))
        path_to_test_config = os.path.join(path_to_tests, "./testconfig.conf")

        self.daemon = LastlineConnector('lastline-test',
                                        configfile=path_to_test_config, work_directory=self.temp_directory,
                                        logfile=os.path.join(self.temp_directory, 'test.log'), debug=True)

        assert self.daemon.validate_config()
        self.daemon.initialize_queue()

    def test_lastline(self):
        database_controller = BinaryDatabaseController(self.daemon.work_queue)
        database_controller.start()

        producer = database_controller.register("provider")

        consumer = database_controller.register("consumer", quick_scan=False)

        CbAPIProducerThread(producer, self.daemon.cb, self.daemon.name, rate_limiter=0,
                            stop_when_done=True).run()

        dirty_flag = threading.Event()
        t = DeepAnalysisThread(consumer, self.daemon.cb, self.daemon.get_provider(),
                               dirty_event=dirty_flag)
        t.start()

        analyzed = 0
        unanalyzed = 1
        while analyzed < 100 or unanalyzed > 0:
            unanalyzed = self.daemon.work_queue.number_unanalyzed()
            print(unanalyzed)
            sleep(.1)
            analyzed = self.daemon.work_queue.number_analyzed()

        t.stop()
        t.join()
