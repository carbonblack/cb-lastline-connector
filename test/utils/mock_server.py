import hashlib
import secrets
import uuid
from collections import namedtuple
from datetime import datetime, timedelta

try:
    import simplejson as json
except ImportError:
    import json

from flask import Flask, request, make_response, Response
from io import StringIO
import zipfile

storage_events_partitions = {"cbevents_2017_03_18_1807": {
    "status": "warm",
    "info": {
        "sizeInBytes": 6132115,
        "startDate": "2017-03-18T18:07:50.758813Z",
        "partitionId": 97639495827456,
        "endDate": "2017-04-07T18:18:31.493403Z",
        "deletedDocs": 0,
        "maxDoc": 1432,
        "userMounted": False,
        "isLegacy": False,
        "segmentCount": 7,
        "numDocs": 1432,
        "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_03_18_1807",
        "schema": "cbevents_v1"
    },
    "name": "cbevents_2017_03_18_1807"
},
    "writer": {
        "status": "hot",
        "info": {
            "sizeInBytes": 825878,
            "startDate": "2017-04-10T18:18:29.834738Z",
            "partitionId": 97769770844160,
            "endDate": None,
            "deletedDocs": 0,
            "maxDoc": 355,
            "userMounted": False,
            "isLegacy": False,
            "segmentCount": 9,
            "numDocs": 355,
            "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_04_10_1818",
            "schema": "cbevents_v1"
        },
        "name": "writer"
    },
    "cbevents_2017_04_07_1818": {
        "status": "warm",
        "info": {
            "sizeInBytes": 20464833,
            "startDate": "2017-04-07T18:18:27.821121Z",
            "partitionId": 97752783781888,
            "endDate": "2017-04-10T18:18:33.612997Z",
            "deletedDocs": 0,
            "maxDoc": 2780,
            "userMounted": False,
            "isLegacy": False,
            "segmentCount": 10,
            "numDocs": 2780,
            "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_04_07_1818",
            "schema": "cbevents_v1"
        },
        "name": "cbevents_2017_04_07_1818"
    },
    "cbevents_2017_02_19_2012": {
        "status": "warm",
        "info": {
            "sizeInBytes": 71,
            "startDate": "2017-02-19T20:12:10.312043Z",
            "partitionId": 97487102279680,
            "endDate": "2017-03-15T18:07:34.821787Z",
            "deletedDocs": 0,
            "maxDoc": 0,
            "userMounted": False,
            "isLegacy": False,
            "segmentCount": 0,
            "numDocs": 0,
            "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_02_19_2012",
            "schema": "cbevents_v1"
        },
        "name": "cbevents_2017_02_19_2012"
    },
    "cbevents_2017_03_15_1807": {
        "status": "warm",
        "info": {
            "sizeInBytes": 41374250,
            "startDate": "2017-03-15T18:07:30.854679Z",
            "partitionId": 97622507585536,
            "endDate": "2017-03-18T18:07:54.721176Z",
            "deletedDocs": 0,
            "maxDoc": 2378,
            "userMounted": False,
            "isLegacy": False,
            "segmentCount": 10,
            "numDocs": 2378,
            "dir": "/var/cb/data/solr5/cbevents/cbevents_2017_03_15_1807",
            "schema": "cbevents_v1"
        },
        "name": "cbevents_2017_03_15_1807"
    }
}

binaryinfoobject = {
    "md5": "6B9EE33E29C0D5303D9C621996061F79",
    "sha256": "A54BA074D509E36B1A27A4E9BD35AABB3CBE1194D95114291C721EB52F25A635",
    "signed": "Signed",
    "timestamp": "2021-07-13T01:45:00.058Z",
    "company_name": "Microsoft Corporation",
    "product_name": "Microsoft Malware Protection",
    "original_filename": "AM_Delta_Patch_1.343.871.0.exe",
    "observed_filename": [
        "c:\\windows\\softwaredistribution\\download\\install\\am_delta_patch_1.343.871.0.exe"
    ],
    "internal_name": "AM_Delta_Patch_1.343.871.0.exe",
    "product_version": "1.343.888.0",
    "file_version": "1.343.888.0",
    "file_desc": "Microsoft Antimalware WU Stub",
    "server_added_timestamp": "2021-07-13T01:45:00.058Z",
    "copied_mod_len": 344512,
    "orig_mod_len": 344512,
    "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
    "digsig_publisher": "Microsoft Corporation",
    "digsig_prog_name": "Microsoft (R) Anti-Malware Signature Package",
    "digsig_issuer": "Microsoft Code Signing PCA 2010",
    "digsig_subject": "Microsoft Corporation",
    "digsig_result": "Signed",
    "digsig_result_code": "0",
    "digsig_sign_time": "2021-07-12T20:30:00Z",
    "is_executable_image": True,
    "is_64bit": True,
    "facet_id": 113377,
    "endpoint": [
        "tl-750-cluster-|3"
    ],
    "group": [
        "smakgroup1"
    ],
    "os_type": "Windows",
    "cb_version": 750,
    "host_count": 1, "last_seen": "2021-07-13T01:46:04.456Z",
    "event_partition_id": [
        106568300363776
    ],
    "watchlists": [
        {
            "wid": "4",
            "value": "2021-07-13T01:46:04.401Z"
        }
    ]
}


def get_random_md5():
    return uuid.uuid4().hex


def get_random_sha256():
    return hashlib.sha256(secrets.token_bytes()).hexdigest()


def get_random_binaryinfo():
    temp = binaryinfoobject.copy()
    temp['md5'] = get_random_md5()
    temp['sha256'] = get_random_sha256()
    return temp


def get_mocked_server(app=None):
    flask_server = app or Flask('cb')
    mock_lastline_server = MockLastlineServer()

    @flask_server.route('/api/v1/binary', methods=['GET', 'POST'])
    def binary_search_endpoint():
        if request.method == 'GET':
            query_string = request.args.get('q', '')
            rows = int(request.args.get('rows', 10))
            start = int(request.args.get('start', 0))
        elif request.method == 'POST':
            parsed_data = json.loads(request.data)
            if 'q' in parsed_data:
                query_string = parsed_data['q']
            else:
                query_string = ''

            if 'rows' in parsed_data:
                rows = int(parsed_data['rows'])
            else:
                rows = 10

            if 'start' in parsed_data:
                start = int(parsed_data['start'])
            else:
                start = 0
        else:
            return make_response('Invalid Request', 500)

        return Response(response=json.dumps(mock_lastline_server.get_binary_search(query_string, rows, start)),
                        mimetype='application/json')

    @flask_server.route('/api/v1/binary/<md5sum>/summary')
    def get_binary_summary(md5sum):
        binary_data = json.dumps(mock_lastline_server.get_binary_summary())
        return Response(response=binary_data, mimetype='application/json')

    @flask_server.route('/api/v1/binary/<md5sum>')
    def get_binary(md5sum):
        binary_data = mock_lastline_server.get_binary()
        return Response(response=binary_data, mimetype='application/zip')

    @flask_server.route('/api/info')
    def info():
        return Response(response=json.dumps(mock_lastline_server.get_api_info()), mimetype='application/json')

    @flask_server.route("/api/v1/storage/events/partition")
    def events_partition():
        return Response(response=json.dumps(mock_lastline_server.get_storage_events()), mimetype="application/json")

    @flask_server.route("/analysis/submit/file.json", methods=["POST"])
    def analysis_submission():
        return Response(response=json.dumps(mock_lastline_server.get_lastline_analysis_submission()),
                        mimetype="application/json")

    @flask_server.route("/analysis/get.json", methods=["POST"])
    def analysis_result():
        return Response(response=json.dumps(mock_lastline_server.get_lastline_analysis_task_result()),
                        mimetype="application/json")

    return flask_server


class MockLastlineResponse(object):
    def __init__(self, success=1):
        self._data = {}
        self.success = 1

    def __dict__(self):
        return {"success": self.success, "data": self._data}

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value


class MockLastlineAnalysisTaskResultResponse(MockLastlineResponse):
    def __init__(self, success=1, score=100, submission=None):
        super().__init__(success)
        self.score = score
        self.submission = submission or datetime.now().timestamp()
        self.data = {"score": score, "submission": self.submission}


class MockLastlineAnalysisRequestResponse(MockLastlineResponse):
    def __init__(self, success=1, expires=None, submission_timestamp=None, task_uuid=None):
        super().__init__(success)
        self.success = success
        self.expires = expires or (datetime.now() + timedelta(hours=1)).timestamp()
        self.submission_timestamp = submission_timestamp or datetime.now().timestamp()
        self.task_uuid = task_uuid or uuid.uuid4().hex
        self.data = {"task_uuid": self.task_uuid, "submission_timestamp": self.submission_timestamp,
                     "expires": self.expires}


class BinarySearchCache(object):

    def __init__(self):
        self.cache = {}
        self.count = 0

    def get_new_result(self, start, rows):
        return {
            'results': [get_random_binaryinfo() for _ in range(start, rows)],
            'terms': '',
            'total_results': rows,
            'start': start,
            'elapsed': 0.1,
            'highlights': [],
            'facets': {}
        }

    def get_empty_result(self, start, rows):
        return {
            'results': [],
            'terms': '',
            'total_results': rows,
            'start': start,
            'elapsed': 0.1,
            'highlights': [],
            'facets': {}
        }

    def get_result(self, query, rows, start):
        if query in self.cache:
            return self.get_empty_result(start=start, rows=rows)
        else:
            result = self.get_new_result(start=start, rows=rows)
            self.cache[query] = result
            return result


class MockLastlineServer(object):

    def __init__(self):
        self.search_cache = BinarySearchCache()

    def get_storage_events(self):
        return storage_events_partitions

    def handle_storage_events(self, request, contest):
        return self.get_storage_events()

    def get_api_info(self):
        return {"version": "7.5.0"}

    def handle_api_info(self, request, context):
        return self.get_api_info()

    def get_binary(self):
        zipfile_contents = StringIO()
        zf = zipfile.ZipFile(zipfile_contents, 'w', zipfile.ZIP_DEFLATED, False)
        zf.writestr('filedata', "HELLOWORLDDEADBEEF")
        zf.writestr('metadata', "NOTHING")
        zf.close()
        return zipfile_contents.getvalue()

    def handle_get_binary(self, request, context):
        return self.get_binary()

    def get_binary_summary(self):
        binary_data = get_random_binaryinfo()
        return binary_data

    def handle_binary_summary(self, request, context):
        return self.get_binary_summary()

    def handle_binary_search(self, request, context):
        search_result = self.get_binary_search("", 9, 0)
        return search_result

    def get_lastline_analysis_submission(self):
        response = MockLastlineAnalysisRequestResponse().__dict__()
        return response

    def handle_lastline_analysis_submission(self, request, context):
        """POST https://localhost:7982/analysis/submit/file.json"""
        return self.get_lastline_analysis_submission()

    def handle_lastline_analysis_task_get_result(self, request, context):
        return self.get_lastline_analysis_task_result()

    def get_binary_search(self, query_string, rows, start):
        return self.search_cache.get_result(query=query_string, rows=rows, start=start)

    def get_lastline_analysis_task_result(self):
        response = MockLastlineAnalysisTaskResultResponse().__dict__()
        return response


if __name__ == '__main__':
    mock_server = get_mocked_server()
    mock_server.run('127.0.0.1', 7982, debug=True)
