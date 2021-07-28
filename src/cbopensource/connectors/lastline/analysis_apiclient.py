#!/usr/bin/python
"""
This is a Python client for the Lastline Analyst API.

The :py:class:`AnalysisClient` class implements the client side of the Lastline Analyst API
methods. It can be imported into Python client code that uses the API.

The client is available at https://analysis.lastline.com/docs/llapi_client/analysis_apiclient.py .

Requirements
+++++++++++++++++++

The Analysis API client requires:

- Python 2.7.
- The python requests module (tested with version 2.2.1).
- The python simplejson module (tested with version 3.6.5).
- To use the client as a python shell, the ipython module (tested with version 2.4.1).

Required python modules can be installed using tools such as apt, pip, or easy_install, e.g.::

    apt-get install python-pycurl=7.19.0-4ubuntu3
    pip install ipython==2.4.1
    easy_install requests==2.2.1

.. note::

    You may want to consider installing the API client and its dependencies inside an isolated
    environment, such as a container, schroot, or VirtualEnv. This allows experimenting with the
    Lastline APIs without affecting system libraries/modules.

Changelog
+++++++++++++++++++++++

The changelog only reflects backwards-incompatible changes; new functionality
may not be reflected in all cases

- 2016-10-05: Stop download of full report details during submission
      Submission functions, such as ``submit_file()``, ``submit_file_hash()``,
      or ``submit_url()``, now default to
      ``full_report_score=ANALYSIS_API_NO_REPORT_DETAILS`` (constant for -1),
      which disables automatic download of the full, detailed analysis report
      if a cached result is immediately available.
      To access the full analysis report, use ``get_result()`` with the task_uuid
      returned as part of the submission result.

- 2016-10-28: Move API client shell to dedicated script.
      The API client shell is now available via analysis_apiclient_shell.py, which povides
      easier access to helper modules provided by the API client module.

Analysis Client Shell
+++++++++++++++++++++++

In addition to the client, an API shell allows running the client from the command line. This
provides an interactive shell for manually sending requests to the Lastline Analyst
API, and it can be used to experiment with the API for analyzing files or URLs. For details,
refer to the :ref:`API Client Shell documentation <analysis_client_shell>`.
"""
import configparser
import io
import cgi
import collections
import datetime
import hashlib
import http.client
import logging
import os
import requests
import simplejson
import ssl
import sys
import time

try:
    from llapi_client import get_proxies_from_config
    from llapi_client import llpcap_apiclient
except ImportError:
    # Non-Lastline environment. Reading from config not support/needed.
    get_proxies_from_config = None
    llpcap_apiclient = None


# printing warnings if this module is used in the context of something else is not meaningful. Only
# if this script is invoked directly should we be printing warnings
if __name__ == "__main__":
    try:
        requests_version = requests.__version__
        if not requests_version.startswith('2.2'):
            raise Exception()
    except Exception:
        requests_version = '?'
        print((
            "Warning: Your version of requests ({}) might not be compatible with this "
            "module.".format(requests_version)
        ), file=sys.stderr)
        print("Officially supported are versions 2.2.x", file=sys.stderr)


# copied these values from Lastline utility code (llutils.api.error)
# to make them available to users of client code. please keep in sync!
ANALYSIS_API_FILE_NOT_AVAILABLE = 101
ANALYSIS_API_UNKNOWN_RESOURCE_TYPE = 102 # undocumented
ANALYSIS_API_UNKNOWN_ANALYSIS_TYPE = 103 # undocumented
ANALYSIS_API_INVALID_CREDENTIALS = 104
ANALYSIS_API_INVALID_UUID = 105
ANALYSIS_API_NO_RESULT_FOUND = 106
ANALYSIS_API_TEMPORARILY_UNAVAILABLE = 107
ANALYSIS_API_PERMISSION_DENIED = 108
ANALYSIS_API_FILE_TOO_LARGE = 109
ANALYSIS_API_INVALID_DOMAIN = 110 # undocumented
ANALYSIS_API_INVALID_BACKEND = 111 # undocumented
ANALYSIS_API_INVALID_D_METADATA = 112
ANALYSIS_API_INVALID_FILE_TYPE = 113
ANALYSIS_API_INVALID_ARTIFACT_UUID = 114
ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED = 115
ANALYSIS_API_INVALID_HASH_ALGORITHM = 116
ANALYSIS_API_INVALID_URL = 117
ANALYSIS_API_INVALID_REPORT_VERSION = 118
ANALYSIS_API_FILE_EXTRACTION_FAILED = 119
ANALYSIS_API_NO_IOC_EXTRACTABLE = 120
ANALYSIS_API_CHILD_TASK_CHAIN_TOO_DEEP = 121
ANALYSIS_API_AUTHENTICATION_REQUIRED = 122
ANALYSIS_API_DATA_NO_LONGER_AVAILABLE = 123
ANALYSIS_API_INVALID_PRIORITY = 124

# other consts
ANALYSIS_API_NO_REPORT_DETAILS = -1
ANALYSIS_API_EXPORT_REPORT_TYPE_OVERVIEW = 'OVERVIEW'
ANALYSIS_API_EXPORT_REPORT_TYPE_ALL = 'ALL'
ANALYSIS_API_EXPORT_REPORT_TYPE_FULL = 'FULL'
ANALYSIS_API_EXPORT_REPORT_TYPES = (
    ANALYSIS_API_EXPORT_REPORT_TYPE_OVERVIEW,
    ANALYSIS_API_EXPORT_REPORT_TYPE_ALL,
    ANALYSIS_API_EXPORT_REPORT_TYPE_FULL
)
ANALYSIS_API_EXPORT_FORMAT_PDF = 'PDF'
ANALYSIS_API_EXPORT_REPORT_FORMATS = (ANALYSIS_API_EXPORT_FORMAT_PDF,)

class Error(Exception):
    """
    Base exception class for this module.
    """


class WaitResultTimeout(Error):
    """
    Waiting for results timed out.
    """
    def __init__(self, msg="Waiting for results timed out"):
        Error.__init__(self, msg)


class InvalidSubApiType(Error):
    """
    Exception for invalid sub API operations.

    The analysis API consists of a number of views (sub APIs):
    (only analysis for now)
    Operations involving parts other than these will
    raise this exceptions.
    """
    def __init__(self, sub_api_type):
        Error.__init__(self)
        self.sub_api_type = sub_api_type

    def __str__(self):
        return "Invalid sub API '%s', expecting one of (%s)" % (
                        self.sub_api_type,
                        ','.join(AnalysisClientBase.SUB_APIS))


class InvalidFormat(Error):
    """
    Invalid format requested.
    """
    def __init__(self, requested_format):
        Error.__init__(self)
        self.format = requested_format

    def __str__(self):
        return "Requested Invalid Format '%s', expecting one of (%s)" % (
                         self.format,
                         ','.join(AnalysisClientBase.FORMATS))


class CommunicationError(Error):
    """
    Contacting Malscape failed.
    """
    def __init__(self, msg=None, error=None):
        Error.__init__(self, msg or error or '')
        self.__error = error

    def internal_error(self):
        return self.__error


class FailedRequestError(CommunicationError):
    """
    Exception class to group communication errors returned
    on failed HTTP requests.
    """
    def __init__(self, msg=None, error=None, status_code=None):
        CommunicationError.__init__(self, msg, error)
        self.__status_code = status_code

    def status_code(self):
        return self.__status_code


class InvalidAnalysisAPIResponse(Error):
    """
    An AnalysisAPI response was not in the expected format
    """


class AnalysisAPIError(Error):
    """
    Analysis API returned an error.

    The `error_code` member of this exception
    is the :ref:`error code returned by the API<error_codes>`.
    """
    def __init__(self, msg, error_code):
        Error.__init__(self)
        self.msg = msg
        self.error_code = error_code

    def __str__(self):
        if self.error_code:
            return "Analysis API error (%s): %s" % (self.error_code, self.msg)
        return "Analysis API error: %s" % self.msg


class RequestError(AnalysisAPIError):
    """
    Exception class to group errors that are permanent request errors when
    following the Lastline Analyst API protocol. These errors indicate a problem
    with the request sent to the server - if you repeat the same request, you
    cannot expect a different error.

    This group excludes temporary errors, such as authentication problems.
    """


class SubmissionInvalidError(RequestError):
    """
    Exception class to group errors that are permanent submission errors. See
    `RequestError` for details.
    """


class FileNotAvailableError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_NOT_AVAILABLE):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidCredentialsError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_CREDENTIALS):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidUUIDError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_UUID):
        RequestError.__init__(self, msg, error_code)


class NoResultFoundError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_NO_RESULT_FOUND):
        AnalysisAPIError.__init__(self, msg, error_code)


class TemporarilyUnavailableError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_TEMPORARILY_UNAVAILABLE):
        AnalysisAPIError.__init__(self, msg, error_code)


class PermissionDeniedError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_PERMISSION_DENIED):
        AnalysisAPIError.__init__(self, msg, error_code)


class FileTooLargeError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_TOO_LARGE):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidFileTypeError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_FILE_TYPE):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidMetadataError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_D_METADATA):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidArtifactError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_ARTIFACT_UUID):
        RequestError.__init__(self, msg, error_code)


class SubmissionLimitExceededError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED):
        AnalysisAPIError.__init__(self, msg, error_code)


class InvalidHashAlgorithmError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_HASH_ALGORITHM):
        RequestError.__init__(self, msg, error_code)


class InvalidURLError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_URL):
        SubmissionInvalidError.__init__(self, msg, error_code)


class InvalidReportVersionError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_REPORT_VERSION):
        RequestError.__init__(self, msg, error_code)


class FileExtractionFailedError(SubmissionInvalidError):
    def __init__(self, msg, error_code=ANALYSIS_API_FILE_EXTRACTION_FAILED):
        SubmissionInvalidError.__init__(self, msg, error_code)


class NoIOCExtractableError(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_NO_IOC_EXTRACTABLE):
        RequestError.__init__(self, msg, error_code)


class DataNoLongerAvailable(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_DATA_NO_LONGER_AVAILABLE):
        RequestError.__init__(self, msg, error_code)


class InvalidPriority(RequestError):
    def __init__(self, msg, error_code=ANALYSIS_API_INVALID_PRIORITY):
        RequestError.__init__(self, msg, error_code)


class AuthenticationError(AnalysisAPIError):
    def __init__(self, msg, error_code=ANALYSIS_API_AUTHENTICATION_REQUIRED):
        AnalysisAPIError.__init__(self, msg, error_code)


class NamedStringIO(io.StringIO):
    """
    A wrapper around StringIO to make it look more like a real file-stream.
    """
    def __init__(self, buf='', name=None):
        # Sanitize buf:
        # None value is transformed into 'None'
        if not buf:
            buf = ''
        io.StringIO.__init__(self, buf)
        self._name = name

    @property
    def name(self):
        """
        Get the name of the BytesIO, might be None
        """
        return self._name


#################
# client
#################


__COMPLETED_TASK_FIELDS = [
    "task_uuid",
    "score",
    "insufficient_task_input_errors",
]
CompletedTask = collections.namedtuple("CompletedTask", __COMPLETED_TASK_FIELDS)
CompletedTask.__new__.__defaults__ = (None, None)

def get_time():
    """
    trivial wrapper around time.time to make testing easier
    """
    return time.time()


def purge_none(d):
    """
    Purge None entries from a dictionary
    """
    for k in list(d.keys()):
        if d[k] is None:
            del d[k]
    return d


def hash_stream(stream, algorithm):
    """
    Compute the hash of a file-like object

    :param stream: stream to hash
    :param algorithm: should be one of hashlib.algorithms
    """
    if hasattr(hashlib, "algorithms"):
        if algorithm not in hashlib.algorithms:
            raise NotImplementedError("Hash function '%s' is not available" %
                                      algorithm)

    try:
        m = hashlib.new(algorithm)
    except ValueError:
        #unsupported hash type
        raise NotImplementedError("Hash function '%s' is not available" %
                                  algorithm)

    while True:
        s = stream.read(4096)
        if not s:
            break
        m.update(s)
    return m.hexdigest()


def parse_datetime(d):
    """
    Parse a datetime as formatted in one of the following formats:

    date: %Y-%m-%d'
    datetime: '%Y-%m-%d %H:%M:%S'
    datetime with microseconds: '%Y-%m-%d %H:%M:%S.%f'

    Can also handle a datetime.date or datetime.datetime object,
    (or anything that has year, month and day attributes)
    and converts it to datetime.datetime
    """
    if hasattr(d, "year") and hasattr(d, "month") and hasattr(d, "day"):
        return datetime.datetime(d.year, d.month, d.day)

    try:
        return datetime.datetime.strptime(
            d, AnalysisClientBase.DATETIME_MSEC_FMT)
    except ValueError: pass

    try:
        return datetime.datetime.strptime(d, AnalysisClientBase.DATETIME_FMT)
    except ValueError: pass

    try:
        return datetime.datetime.strptime(d, AnalysisClientBase.DATE_FMT)
    except ValueError:
        raise ValueError("Date '%s' does not match format '%s'" % (
                         d, "%Y-%m-%d[ %H:%M:%S[.%f]]'"))


def get_direction(is_download):
    """
    Returns the transfer direction for a file captured during an SMB or FTP request.

    :param is_download: True if request was an SMB or FTP download.
    :return: "FROM_SERVER" or "TO_SERVER"
    """
    if is_download or is_download is None:
        return "FROM_SERVER"
    return "TO_SERVER"


class TaskCompletion(object):
    """
    Helper class to get score for all completed tasks

    Sample usage:

    tc = TaskCompletion(my_analysis_client)
    for completed_task in tc.get_completed(start,end):
        print completed_task.task_uuid, completed_task.score

    """
    def __init__(self, analysis_client):
        """
        :param analysis_apiclient.AnalysisClientBase analysis_client: Client to use for
            issuing get-completed requests
        """

        self.__analysis_client = analysis_client

    def get_completed(self, after, before):
        """
        Return scores and additional metadata of tasks completed in the specified time range.

        This takes care of using the analysis API's pagination
        to make sure it gets all tasks.

        :param after: datetime.datetime
        :param before: datetime.datetime

        :yield: sequence of `CompletedTask`

        :raise: InvalidAnalysisAPIResponse if response
            does not have the format we expect
        """
        try:
            while True:
                result = self.__analysis_client.get_completed_with_metadata(
                    after=after,
                    before=before)

                data = result["data"]
                tasks = data["tasks"]
                if tasks:
                    for task in tasks:
                        yield CompletedTask(
                            task_uuid=task['task_uuid'],
                            score=task['score'],
                            insufficient_task_input_errors=task.get(
                                'insufficient_task_input_errors'
                            ),
                        )

                # NOTE: Even if no tasks have been returned, the API may still have returned us
                # the flag to query again (e.g., on a sliding window of time).
                try:
                    more = int(data["more_results_available"])
                except (KeyError, TypeError, ValueError):
                    # this flag was not in the initial API specs, so be a bit loose about parsing it
                    more = 0
                if not more:
                    break

                last_ts = parse_datetime(data["before"])
                if last_ts >= before:
                    break

                after = last_ts

        except (KeyError, ValueError, TypeError, AttributeError):
            # attributeError needed in case iteritems is missing (not a dict)
            # let's give it the trace of the original exception, so we know
            # what the specific problem is!
            trace = sys.exc_info()[2]
            raise InvalidAnalysisAPIResponse(
                "Unable to parse response to get_completed()").with_traceback(trace)


class SubmissionTracker(object):
    """
    Helper class to track the state of submissions until they're completed

    :param analysis_client: analysis_apiclient.AnalysisClientBase
    :param task_completion: analysis_apiclient.TaskCompletion or None
        If not provided, will create one from the analysis_client.
        Providing this parameter explicitly is mainly for testing.

     - `track_submission()` is used to add the submission to the list of tasks
        that we are keeping track of.
     - `get_completed()` is used to get the results of tracked submissions
        that have completed so far

    Invocations of the two methods can be interleaved to add new tasks to keep
    track of while others are still waiting to be completed.
    """
    def __init__(self, analysis_client, task_completion=None):
        self.__analysis_client = analysis_client
        if not task_completion:
            task_completion = TaskCompletion(analysis_client)
        self.__task_completion = task_completion
        # tasks we are currently tracking
        self.__tracked_uuids = set()
        # how far back in time we have to go for completion call
        self.__min_timestamp = None

    @property
    def min_timestamp(self):
        """
        Minimum timestamp from which next calls to get_completed call will start.

        It may be useful to access this property
        to serialize the state of the SubmissionTracker.

        :rtype: datetime.datetime
        """
        return self.__min_timestamp

    @property
    def num_tracked_uuids(self):
        return len(self.__tracked_uuids)

    def get_tracked_uuids(self):
        """
        Return the current tracked uuids

        It may be useful to access this property
        to serialize the state of the SubmissionTracker.

        :return: Sequence of task_uuids
        """
        return set(self.__tracked_uuids)

    def track_submission(self, task_uuid, submission_utc_timestamp):
        """
        Start keeping track of the specified submission

        :param task_uuid: UUID of submission to track
        :type task_uuid: str
        :param submission_utc_timestamp: Timestamp of the submission according to
            the API server. A correct API timestamp can be obtained by
            invoking `AnalysiClientBase.get_api_timestamp()`.
            Providing a timestamp before the actual submission timestamp
            will also work but may lead to less efficient use
            of the get_completed API.
        :type submission_utc_timestamp: datetime.datetime
        """
        self.__tracked_uuids.add(task_uuid)
        if self.__min_timestamp:
            self.__min_timestamp = min(
                self.__min_timestamp, submission_utc_timestamp)
        else:
            self.__min_timestamp = submission_utc_timestamp

    def get_completed(self):
        """
        Get results for tracked tasks that have completed so far

        Once a completed task is returned by this method,
        it will be removed from the set of tasks that are being tracked,
        so it will not be returned again by later calls to this method.

        :yield: sequence of `CompletedTask`

        :raise: InvalidAnalysisAPIResponse if response
            does not have the format we expect
        """
        if not self.__tracked_uuids:
            return

        # cannot be None as otherwise we'd have no tracked uuids
        assert self.__min_timestamp is not None, "SubmissionTracker has no min_timestamp!"
        after = self.__min_timestamp
        before = self.__analysis_client.get_api_utc_timestamp()

        for completed_task in self.__task_completion.get_completed(after, before):
            try:
                self.__tracked_uuids.remove(completed_task.task_uuid)
                yield completed_task
            except KeyError:
                # not a task we are tracking, so ignore it
                pass

        # we've examined all tasks up to this point, so move the starting time
        self.__min_timestamp = before


class MockSession(object):
    """
    This class acts as a drop-in replacement for the python-requests Session object in cases where
    the client should not use a real session. This is useful in case where
    - the API server does not support sessions. This feature was added a while back, but we want to
      make sure that the latest client works with older versions of the API server, or
    - a session introduces overhead rather than reduce it.

    NOTE: This session implementation will embed the provided API credentials (if any) in each API
    request, including GET requests. When using this class, ensure that the client does not invoke
    GET requests to avoid leaking credentials into server logs.

    NOTE: This is not a drop-in replacement for `requests.Session`. It only implements those parts
    of the Session object's interface that we actually use in the `AnalysisAPIClient` class.
    """
    def __init__(self, credentials=None, logger=None):
        """
        :param dict|None credentials: Optional credentials to embed in each API request
        :param logging.Logger|None logger: if provided, should be a python logging.Logger object
            or object with similar interface.
        """
        self.__credentials = credentials
        self.__requests_session = None
        self.__logger = logger

    def request(self, method, url, **kwargs):
        """
        Perform a request on this session - for more details, refer to `requests.Session.request()`
        """
        if self.__requests_session is None:
            self.__requests_session = requests.session()

        data = {}
        try:
            data = kwargs.pop('data')
        except KeyError:
            pass
        else:
            # just to be on the safe side if someone explicitly passed in None
            if data is None:
                data = {}

        # rewrite GET to POST: see class doc-string
        if method.upper() == 'GET':
            method = 'POST'
            try:
                params = kwargs.pop('params')
            except KeyError:
                pass  # no GET args to deal with
            else:
                if params:
                    data.update(params)
            if self.__logger:
                self.__logger.debug(
                    "Rewrote %s %s to POST, moved %d GET args", method, url,
                    len(params) if params else 0)

        # now embed the credentials if needed
        if self.__credentials is not None:
            for key, value in self.__credentials.items():
                if key not in data:
                    data[key] = value

        # now do the actual request
        return self.__requests_session.request(method, url, data=data, **kwargs)

    def close(self):
        """
        Tear down this session object - for more details, refer to `requests.Session.close()`
        """
        self.__requests_session.close()


class AnalysisClientBase(object):
    """
    A client for the Lastline analysis API.

    This is an abstract base class: concrete
    subclasses just need to implement the _api_request
    method to actually send the API request to the server.

    :param base_url: URL where the lastline analysis API is located. (required)
    :param logger: if provided, should be a python logging.Logger object
        or object with similar interface.
    """
    SUB_APIS = ('analysis', 'management', 'authentication')

    DATETIME_FMT = '%Y-%m-%d %H:%M:%S'
    DATETIME_MSEC_FMT = DATETIME_FMT + '.%f'
    DATE_FMT = '%Y-%m-%d'

    FORMATS = ["json", "xml", "pdf", "rtf"]

    REQUEST_PERFDATA = False

    ERRORS = {
        ANALYSIS_API_FILE_NOT_AVAILABLE: FileNotAvailableError,
        ANALYSIS_API_INVALID_CREDENTIALS: InvalidCredentialsError,
        ANALYSIS_API_INVALID_UUID: InvalidUUIDError,
        ANALYSIS_API_NO_RESULT_FOUND: NoResultFoundError,
        ANALYSIS_API_TEMPORARILY_UNAVAILABLE: TemporarilyUnavailableError,
        ANALYSIS_API_PERMISSION_DENIED: PermissionDeniedError,
        ANALYSIS_API_FILE_TOO_LARGE: FileTooLargeError,
        ANALYSIS_API_INVALID_FILE_TYPE: InvalidFileTypeError,
        ANALYSIS_API_INVALID_DOMAIN: InvalidMetadataError,
        ANALYSIS_API_INVALID_D_METADATA: InvalidMetadataError,
        ANALYSIS_API_INVALID_ARTIFACT_UUID: InvalidArtifactError,
        ANALYSIS_API_SUBMISSION_LIMIT_EXCEEDED: SubmissionLimitExceededError,
        ANALYSIS_API_INVALID_HASH_ALGORITHM: InvalidHashAlgorithmError,
        ANALYSIS_API_INVALID_URL: InvalidURLError,
        ANALYSIS_API_INVALID_REPORT_VERSION: InvalidReportVersionError,
        ANALYSIS_API_FILE_EXTRACTION_FAILED: FileExtractionFailedError,
        ANALYSIS_API_NO_IOC_EXTRACTABLE: NoIOCExtractableError,
        ANALYSIS_API_DATA_NO_LONGER_AVAILABLE: DataNoLongerAvailable,
        ANALYSIS_API_INVALID_PRIORITY: InvalidPriority,
        ANALYSIS_API_AUTHENTICATION_REQUIRED: AuthenticationError,
    }

    HTTP_ERRORS = {
        http.client.UNAUTHORIZED: AuthenticationError,
        http.client.FORBIDDEN: PermissionDeniedError,
    }

    SUPPORTED_IOC_PCAP_VERSION = 2

    def __init__(self, base_url, use_cdn=None, logger=None, config=None):
        self.__logger = logger
        self.__base_url = base_url
        self.__use_cdn = use_cdn
        self.__config = config

    def _logger(self):
        return self.__logger

    def _build_url(self, sub_api, parts, requested_format="json"):
        if sub_api not in self.SUB_APIS:
            raise InvalidSubApiType(sub_api)
        if requested_format not in self.FORMATS:
            raise InvalidFormat(requested_format)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts) + ".%s"
        params = [self.__base_url, sub_api] + parts + [requested_format]
        return pattern % tuple(params)

    def _build_file_download_url(self, sub_api, parts):
        """
        Generate a URL to a direct file download
        """
        if sub_api not in self.SUB_APIS:
            raise InvalidSubApiType(sub_api)
        num_parts = 2 + len(parts)
        pattern = "/".join(["%s"] * num_parts)
        params = [self.__base_url, sub_api] + parts
        return pattern % tuple(params)

    def _check_file_like(self, f, param_name):
        if not hasattr(f, 'read'):
            raise AttributeError("The %s parameter is not a file-like object" %
                                 param_name)

    def submit_exe_hash(self,
                        md5=None,
                        sha1=None,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        raw=False,
                        verify=True):
        """
        Submit a file by hash.

        *Deprecated*. Use `submit_file_hash()`
        """
        return self.submit_file_hash(md5, sha1,
                        download_ip=download_ip,
                        download_port=download_port,
                        download_url=download_url,
                        download_host=download_host,
                        download_path=download_path,
                        download_agent=download_agent,
                        download_referer=download_referer,
                        download_request=download_request,
                        full_report_score=full_report_score,
                        bypass_cache=bypass_cache,
                        raw=raw,
                        verify=verify)

    def submit_file_hash(self,
                        md5=None,
                        sha1=None,
                        sha256=None,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        password=None,
                        password_candidates=None,
                        backend=None,
                        require_file_analysis=True,
                        mime_type=None,
                        analysis_timeout=None,
                        analysis_env=None,
                        allow_network_traffic=None,
                        filename=None,
                        keep_file_dumps=None,
                        keep_memory_dumps=None,
                        keep_behavior_log=None,
                        push_to_portal_account=None,
                        raw=False,
                        verify=True,
                        server_ip=None,
                        server_port=None,
                        server_host=None,
                        client_ip=None,
                        client_port=None,
                        is_download=True,
                        protocol="http",
                        apk_package_name=None,
                        report_version=None,
                        analysis_task_uuid=None,
                        analysis_engine=None,
                        task_metadata=None,
                        priority=None,
                        bypass_prefilter=None,
                        fast_analysis=None):
        """
        Submit a file by hash.

        One of the md5, sha1, or sha256 parameters must be provided.
        If both are provided, they should be consistent.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.submit_file`.

        :param md5: md5 hash of file.
        :param sha1: sha1 hash of file.
        :param sha256: sha256 hash of file.
        :param download_ip: DEPRECATED! Use server_ip instead.
        :param download_port: DEPRECATED! Use server_port instead.
        :param download_url: DEPRECATED! replaced by the download_host
            and download_path parameters
        :param download_host: hostname of the server-side endpoint of
            the connection, as a string of bytes (not unicode).
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param password: password used to analyze password-protected or
            encrypted content (such as archives or documents)
        :param password_candidates: List of passwords used to analyze password-protected or
            encrypted content (such as archives or documents)
        :param require_file_analysis: if True, the submission requires an
            analysis run to be started. If False, the API will attempt to
            base a decision solely on static information such as
            download source reputation and hash lookups. Requires special
            permissions; Lastline-internal/do not use
        :param mime_type: the mime-type of the file; This value should be
            set when require_file_analysis is True to enforce getting the
            most information available
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param analysis_env: environment in which to run analysis. This includes
            the operating system as well as version of tools such as Microsoft
            Office. Example usage:
            - windows7:office2003, or
            - windowsxp
            By default, analysis will run on all available operating systems
            using the most applicable tools.
        :param allow_network_traffic: if False, all network connections will be
            redirected to a honeypot. Requires special permissions.
        :param filename: filename to use during analysis. If none is passed,
            the analysis engine will pick an appropriate name automatically.
            An easy way to pass this value is to use 'file_stream.name' for most
            file-like objects
        :param keep_file_dumps: if True, all files generated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_memory_dumps: if True, all buffers allocated during
            analysis will be kept for post-processing. NOTE: This can generate
            *very* large volumes of data and is not recommended. Requires
            special permissions
        :param keep_behavior_log: if True, the raw behavior log extracted during
            analysis will be kept for post-processing. NOTE: This can generate
            *very very* large volumes of data and is not recommended. Requires
            special permissions
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified account
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw json results of the API query
        :param server_ip: ASCII dotted-quad representation of the IP address of
            the server-side endpoint.
        :param server_port: integer representation of the port number
            of the server-side endpoint of the flow tuple.
        :param server_host: DEPRECATED! Don't use
        :param client_ip: ASCII dotted-quad representation of the IP address of
            the client-side endpoint.
        :param client_port: integer representation of the port number
            of the client-side endpoint of the flow tuple.
        :param is_download: Boolean; True if the transfer happened in the
            server -> client direction, False otherwise (client -> server).
        :param protocol: app-layer protocol in which the file got
            transferred. Short ASCII string.
        :param apk_package_name: package name for APK files. Don't specify
            manually.
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param task_metadata: optional task-metadata to upload. Requires special
            permissions; Lastline-internal/do not use
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest).
            Setting priority to any value other than 1 requires special permissions.
        :param bypass_prefilter: Boolean; If True, file is submitted to all supported
            analysis components without prior static analysis. Requires special permissions.
        :param fast_analysis: Boolean; If True, file is submitted only to fast analyzers (static)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # this parameter was introduced into the LLAPI-client at some point, but
        # it's actually not supported by the API!
        _unused = server_host

        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        url = self._build_url("analysis", ["submit", "file"])
        # These options require special permissions, so we should not set them
        # if not specified
        if allow_network_traffic is not None:
            allow_network_traffic = allow_network_traffic and 1 or 0
        if keep_file_dumps is not None:
            keep_file_dumps = keep_file_dumps and 1 or 0
        if keep_memory_dumps is not None:
            keep_memory_dumps = keep_memory_dumps and 1 or 0
        if keep_behavior_log is not None:
            keep_behavior_log = keep_behavior_log and 1 or 0
        if bypass_prefilter is not None:
            bypass_prefilter = bypass_prefilter and 1 or 0
        if fast_analysis is not None:
            fast_analysis = fast_analysis and 1 or 0
        params = purge_none({
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "full_report_score": full_report_score,
            "bypass_cache": bypass_cache and 1 or None,
            "password": password,
            "require_file_analysis": require_file_analysis and 1 or 0,
            "mime_type": mime_type,
            "download_ip": download_ip,
            "download_port": download_port,
            # analysis-specific options:
            "analysis_timeout": analysis_timeout or None,
            "analysis_env": analysis_env,
            "allow_network_traffic": allow_network_traffic,
            "filename": filename,
            "keep_file_dumps": keep_file_dumps,
            "keep_memory_dumps": keep_memory_dumps,
            "keep_behavior_log": keep_behavior_log,
            "push_to_portal_account": push_to_portal_account or None,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "client_port": client_port,
            "direction": get_direction(is_download),
            "protocol": protocol,
            "apk_package_name": apk_package_name,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid,
            "analysis_engine": analysis_engine,
            "priority": priority,
            "bypass_prefilter": bypass_prefilter,
            "fast_analysis": fast_analysis,
        })
        # using and-or-trick to convert to a StringIO if it is not None
        # this just wraps it into a file-like object
        files = purge_none({
            "download_url": download_url is not None and \
                               io.StringIO(download_url) or None,
            "download_host": download_host is not None and \
                               io.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                               io.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                               io.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                               io.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                               io.StringIO(download_request) or None,
            "task_metadata": io.StringIO(simplejson.dumps(task_metadata))
                if task_metadata is not None else None,
            # NOTE: We enforce that the given collection is a unique list (set cannot be
            # serialized). Further, if we are given an empty collection, we don't bother sending
            # the json
            "password_candidates": io.StringIO(simplejson.dumps(
                list(set(password_candidates)))) if password_candidates else None,
        })
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)

    def submit_exe_file(self,
                        file_stream,
                        download_ip=None,
                        download_port=None,
                        download_url=None,
                        download_host=None,
                        download_path=None,
                        download_agent=None,
                        download_referer=None,
                        download_request=None,
                        full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                        bypass_cache=None,
                        delete_after_analysis=False,
                        raw=False,
                        verify=True):
        """
        Submit a file by uploading it.

        *Deprecated*. Use `submit_file()`
        """
        return self.submit_file(file_stream,
                        download_ip=download_ip,
                        download_port=download_port,
                        download_url=download_url,
                        download_host=download_host,
                        download_path=download_path,
                        download_agent=download_agent,
                        download_referer=download_referer,
                        download_request=download_request,
                        full_report_score=full_report_score,
                        bypass_cache=bypass_cache,
                        delete_after_analysis=delete_after_analysis,
                        raw=raw,
                        verify=verify)

    def submit_file(self, file_stream,
                    download_ip=None,
                    download_port=None,
                    download_url=None,
                    download_host=None,
                    download_path=None,
                    download_agent=None,
                    download_referer=None,
                    download_request=None,
                    full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                    bypass_cache=None,
                    delete_after_analysis=None,
                    backend=None,
                    analysis_timeout=None,
                    analysis_env=None,
                    allow_network_traffic=None,
                    filename=None,
                    keep_file_dumps=None,
                    keep_memory_dumps=None,
                    keep_behavior_log=None,
                    push_to_portal_account=None,
                    raw=False,
                    verify=True,
                    server_ip=None,
                    server_port=None,
                    server_host=None,
                    client_ip=None,
                    client_port=None,
                    is_download=True,
                    protocol="http",
                    apk_package_name=None,
                    password=None,
                    password_candidates=None,
                    report_version=None,
                    analysis_task_uuid=None,
                    analysis_engine=None,
                    task_metadata=None,
                    priority=None,
                    bypass_prefilter=None,
                    fast_analysis=None):
        """
        Submit a file by uploading it.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.submit_file`.

        :param file_stream: file-like object containing
            the file to upload.
        :param download_ip: DEPRECATED! Use server_ip instead.
        :param download_port: DEPRECATED! Use server_port instead.
        :param download_url: DEPRECATED! replaced by the download_host
            and download_path parameters
        :param download_host: hostname of the server-side endpoint of
            the connection, as a string of bytes (not unicode).
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param delete_after_analysis: if True, the backend will delete the
            file after analysis is done (and noone previously submitted
            this file with this flag set)
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param analysis_env: environment in which to run analysis. This includes
            the operating system as well as version of tools such as Microsoft
            Office. Example usage:
            - windows7:office2003, or
            - windowsxp
            By default, analysis will run on all available operating systems
            using the most applicable tools.
        :param allow_network_traffic: if False, all network connections will be
            redirected to a honeypot. Requires special permissions.
        :param filename: filename to use during analysis. If none is passed,
            the analysis engine will pick an appropriate name automatically.
            An easy way to pass this value is to use 'file_stream.name' for most
            file-like objects
        :param keep_file_dumps: if True, all files generated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_memory_dumps: if True, all buffers allocated during
            analysis will be kept for post-processing. NOTE: This can generate
            large volumes of data and is not recommended. Requires special
            permissions
        :param keep_behavior_log: if True, the raw behavior log extracted during
            analysis will be kept for post-processing. NOTE: This can generate
            *very very* large volumes of data and is not recommended. Requires
            special permissions
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified username
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw JSON results of the API query
        :param server_ip: ASCII dotted-quad representation of the IP address of
            the server-side endpoint.
        :param server_port: integer representation of the port number
            of the server-side endpoint of the flow tuple.
        :param server_host: DEPRECATED! Don't use
        :param client_ip: ASCII dotted-quad representation of the IP address of
            the client-side endpoint.
        :param client_port: integer representation of the port number
            of the client-side endpoint of the flow tuple.
        :param is_download: Boolean; True if the transfer happened in the
            server -> client direction, False otherwise (client -> server).
        :param protocol: app-layer protocol in which the file got
            transferred. Short ASCII string.
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param apk_package_name: package name for APK files. Don't specify
            manually.
        :param password: password used to analyze password-protected or
                encrypted content (such as archives or documents)
        :param password_candidates: List of passwords used to analyze password-protected or
                encrypted content (such as archives or documents)
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param task_metadata: optional task-metadata to upload. Requires special
            permissions; Lastline-internal/do not use
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest)
            Setting priority to any value other than 1 requires special permissions.
        :param bypass_prefilter: Boolean; If True, file is submitted to all supported
            analysis components without prior static analysis. Requires special permissions.
        :param fast_analysis: Boolean; If True, file is submitted only to fast analyzers (static)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # this parameter was introduced into the LLAPI-client at some point, but
        # it's actually not supported by the API!
        _unused = server_host

        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        if filename is None and hasattr(file_stream, 'name'):
            filename = os.path.basename(file_stream.name)

        self._check_file_like(file_stream, "file_stream")
        url = self._build_url("analysis", ["submit", "file"])
        # These options require special permissions, so we should not set them
        # if not specified
        if allow_network_traffic is not None:
            allow_network_traffic = allow_network_traffic and 1 or 0
        if keep_file_dumps is not None:
            keep_file_dumps = keep_file_dumps and 1 or 0
        if keep_memory_dumps is not None:
            keep_memory_dumps = keep_memory_dumps and 1 or 0
        if keep_behavior_log is not None:
            keep_behavior_log = keep_behavior_log and 1 or 0
        if bypass_prefilter is not None:
            bypass_prefilter = bypass_prefilter and 1 or 0
        if fast_analysis is not None:
            fast_analysis = fast_analysis and 1 or 0
        params = purge_none({
            "bypass_cache": bypass_cache and 1 or None,
            "full_report_score": full_report_score,
            "delete_after_analysis": delete_after_analysis and 1 or 0,
            "download_ip": download_ip,
            "download_port": download_port,
            # analysis-specific options:
            "analysis_timeout": analysis_timeout or None,
            "analysis_env": analysis_env,
            "allow_network_traffic": allow_network_traffic,
            "filename": filename,
            "keep_file_dumps": keep_file_dumps,
            "keep_memory_dumps": keep_memory_dumps,
            "keep_behavior_log": keep_behavior_log,
            "push_to_portal_account": push_to_portal_account or None,
            "server_ip": server_ip,
            "server_port": server_port,
            "client_ip": client_ip,
            "client_port": client_port,
            "direction": get_direction(is_download),
            "protocol": protocol,
            "apk_package_name": apk_package_name,
            "password": password,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid,
            "analysis_engine": analysis_engine,
            "priority": priority,
            "bypass_prefilter": bypass_prefilter,
            "fast_analysis": fast_analysis,
        })

        # using and-or-trick to convert to a StringIO if it is not None
        # this just wraps it into a file-like object
        files = purge_none({
            # If an explicit filename was provided, we can pass it down to
            # python-requests to use it in the multipart/form-data. This avoids
            # having python-requests trying to guess the filenam based on stream
            # attributes.
            #
            # The problem with this is that, if the filename is not ASCII, then
            # this triggers a bug in flask/werkzeug which means the file is
            # thrown away. Thus, we just force an ASCII name
            "file": ('dummy-ascii-name-for-file-param', file_stream),
            "download_url": download_url is not None and \
                                  io.StringIO(download_url) or None,
            "download_host": download_host is not None and \
                                  io.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                                  io.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                                  io.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                                  io.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                                  io.StringIO(download_request) or None,
            "task_metadata": io.StringIO(simplejson.dumps(task_metadata))
                if task_metadata is not None else None,
            # NOTE: We enforce that the given collection is a unique list (set cannot be
            # serialized). Further, if we are given an empty collection, we don't bother sending
            # the json
            "password_candidates": io.StringIO(simplejson.dumps(
                list(set(password_candidates)))) if password_candidates else None,
        })
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)

    def submit_file_metadata(self, md5, sha1,
                                   download_ip,
                                   download_port,
                                   download_host=None,
                                   download_path=None,
                                   download_agent=None,
                                   download_referer=None,
                                   download_request=None,
                                   raw=False,
                                   verify=True):
        """
        Submit metadata regarding a file download.

        *Deprecated*. Do not use.

        Both the md5 and the sha1 parameter must be provided.

        :param md5: md5 hash of the downloaded file.
        :param sha1: sha1 hash of the downloaded file.
        :param download_ip: ASCII dotted-quad representation of the IP address
            from which the file has been downloaded
        :param download_port: integer representation of the port number
            from which the file has been downloaded
        :param download_host: host from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_path: host path from which the submitted file
            was originally downloaded, as a string of bytes (not unicode)
        :param download_agent: HTTP user-agent header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_referer: HTTP referer header that was used
            when the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param download_request: full HTTP request with
            which the submitted file was originally downloaded,
            as a string of bytes (not unicode)
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw json results of the API query
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["submit", "download"])
        params = {
            "md5": md5,
            "sha1": sha1,
            "download_ip": download_ip,
            "download_port": download_port
        }
        #using and-or-trick to convert to a StringIO if it is not None
        #this just wraps it into a file-like object
        files = {
            "download_host": download_host is not None and \
                                   io.StringIO(download_host) or None,
            "download_path": download_path is not None and \
                                   io.StringIO(download_path) or None,
            "download_agent": download_agent is not None and \
                                   io.StringIO(download_agent) or None,
            "download_referer": download_referer is not None and \
                                   io.StringIO(download_referer) or None,
            "download_request": download_request is not None and \
                                   io.StringIO(download_request) or None

        }
        purge_none(files)
        purge_none(params)
        return self._api_request(url, params, files=files, post=True,
                                 raw=raw, verify=verify)

    def submit_url(self,
                   url,
                   referer=None,
                   full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                   bypass_cache=None,
                   backend=None,
                   analysis_timeout=None,
                   push_to_portal_account=None,
                   raw=False,
                   verify=True,
                   user_agent=None,
                   report_version=None,
                   analysis_task_uuid=None,
                   analysis_engine=None,
                   priority=None,
                   task_metadata=None,
                   fast_analysis=None,
                   password_candidates=None):
        """
        Submit a url.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.submit_url`.

        :param url: url to analyze
        :param referer: referer header to use for analysis
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param analysis_timeout: timeout in seconds after which to terminate
            analysis. The analysis engine might decide to extend this timeout
            if necessary. If all analysis subjects terminate before this timeout
            analysis might be shorter
        :param push_to_portal_account: if set, a successful submission will be
            pushed to the web-portal using the specified account
        :param backend: DEPRECATED! Don't use
        :param verify: if False, disable SSL-certificate verification
        :param raw: if True, return the raw JSON results of the API query
        :param report_version: Version name of the Report that will be returned
                               (optional);
        :param user_agent: user agent header to use for analysis
        :param analysis_task_uuid: if the call is used to create a child task,
            it specifies the current analysis task UUID; None otherwise.
            Lastline-internal/do not use.
        :param analysis_engine: if analysis_task_uuid is provided, it specifies
            the sandbox it refers to; None otherwise. Lastline-internal/do not
            use.
        :param priority: Priority level to set for this analysis. Priority should
            be between 1 and 10 (1 is the lowest priority, 10 is the highest).
            Setting priority to any value other than 1 requires special permissions.
        :param task_metadata: optional task-metadata to upload. Requires special
            permissions; Lastline-internal/do not use
        :param fast_analysis: Boolean; If True, url is submitted only to fast analyzers (static)
        :param password_candidates: List of passwords used to analyze password-protected or
            encrypted content from the URL.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        if self.__logger and backend:
            self.__logger.warning("Ignoring deprecated parameter 'backend'")

        api_url = self._build_url("analysis", ["submit", "url"])

        if fast_analysis is not None:
            fast_analysis = fast_analysis and 1 or 0

        params = purge_none({
            "url":url,
            "referer":referer,
            "full_report_score":full_report_score,
            "bypass_cache":bypass_cache and 1 or None,
            "analysis_timeout": analysis_timeout or None,
            "push_to_portal_account": push_to_portal_account or None,
            "user_agent": user_agent or None,
            "report_version": report_version,
            "analysis_task_uuid": analysis_task_uuid or None,
            "analysis_engine": analysis_engine,
            "priority": priority,
            "fast_analysis": fast_analysis,
        })

        files = purge_none({
            "task_metadata": io.StringIO(simplejson.dumps(task_metadata))
            if task_metadata is not None else None,
            # NOTE: We enforce that the given collection is a unique list (set cannot be
            # serialized). Further, if we are given an empty collection, we don't bother sending
            # the json
            "password_candidates": io.StringIO(simplejson.dumps(
                list(set(password_candidates)))) if password_candidates else None,
        })

        return self._api_request(api_url, params, files=files, post=True,
                                 raw=raw, verify=verify)

    def get_result(self,
                   uuid,
                   report_uuid=None,
                   full_report_score=None,
                   include_scoring_components=None,
                   raw=False,
                   requested_format="json",
                   verify=True,
                   report_version=None,
                   allow_datacenter_redirect=None):
        """
        Get results for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_results`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: if set, include this report in the result.
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param include_scoring_components: if True, the result will contain
            details of all components contributing to the overall score.
            Requires special permissions
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON, XML, PDF, or RTF.
            If format is not JSON, this implies `raw`.
        :param report_version: Version of the report to be returned
            If *report_uuid* is not specified, this parameter is ignored.
            (optional)
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # better: use 'get_results()' but that would break
        # backwards-compatibility
        url = self._build_url('analysis', ['get'],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'full_report_score': full_report_score,
            'include_scoring_components': include_scoring_components and 1 or 0,
            'report_version': report_version,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != 'json':
            raw = True
        # NOTE: This API request may return real HTTP status-codes (and errors)
        # directly when fetching IOC reports.
        try:
            result = self._api_request(url,
                                       params,
                                       raw=raw,
                                       requested_format=requested_format,
                                       verify=verify)
        except FailedRequestError as exc:
            status_code = str(exc.status_code())

            if status_code == '404':
                raise InvalidUUIDError(str(exc))

            if status_code == '412':
                raise NoResultFoundError(str(exc))

            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        # Legacy support:
        # results are always returned as strings no matter
        # the content disposition of the server response.
        if isinstance(result, NamedStringIO):
            return result.read()

        return result

    def get_result_summary(self, uuid, raw=False,
                           requested_format="json",
                           score_only=False,
                           verify=True,
                           allow_datacenter_redirect=None):
        """
        Get result summary for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_result`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        :param score_only: if True, return even less data (only score and
            threat/threat-class classification).
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_result"],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'score_only': score_only and 1 or 0,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_result_activities(self, uuid, raw=False,
                              requested_format="json",
                              verify=True,
                              allow_datacenter_redirect=None):
        """
        Get the behavior/activity information for a previously submitted
        analysis task.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_result_activities`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_result_activities"],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_report_activities(self, uuid, report_uuid, raw=False,
                              requested_format="json",
                              verify=True,
                              allow_datacenter_redirect=None):
        """
        Get the behavior/activity information for a specific analysis report.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_report_activities`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_report_activities"],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != "json":
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_result_artifact(self, uuid, report_uuid, artifact_name, password_protected=None,
                            raw=False, verify=True, allow_datacenter_redirect=None):
        """
        Get artifact generated by an analysis result for a previously
        submitted analysis task.

        NOTE: Consider using `get_report_artifact()` if the artifact is bound to a specific
        analysis report (which it is in practically all cases.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :param artifact_name: the name of the artifact as mentioned in the
            given report in the dictionary returned by get_result().
        :param str password_protected: If provided, use this password to create a zip which will
            contain the artifact being fetched. The password provided should be using only
            ASCII characters and have max length of 128 characters
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # NOTE: we cannot simply use "get_report_artifact" in this function, because that
        # function does not allow returning JSON/XML formatted data
        url = self._build_file_download_url("analysis",
                                             ["get_result_artifact"])
        params = purge_none({
            'uuid': uuid,
            'artifact_uuid': "%s:%s" % (report_uuid, artifact_name),
            'password_protected': password_protected,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })

        # NOTE: This API request is completely different because it
        # returns real HTTP status-codes (and errors) directly
        try:
            result = self._api_request(url, params, requested_format='raw',
                                       raw=raw, verify=verify)
            if not result.len:
                raise InvalidArtifactError("The artifact is empty")

        except FailedRequestError as exc:
            status_code = str(exc.status_code())

            if status_code == '401':
                raise PermissionDeniedError(
                    "Permission denied to access artifacts")

            if status_code == '404':
                raise InvalidArtifactError(str(exc))

            if status_code == '410':
                raise InvalidArtifactError(
                    "The artifact is no longer available")

            if status_code == '412':
                raise InvalidUUIDError(str(exc))

            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        if not result.len:
            raise InvalidArtifactError("The artifact is empty")
        return result

    def get_report_artifact(
        self, uuid, report_uuid, artifact_name, password_protected=None, verify=True,
            allow_datacenter_redirect=None
    ):
        """
        Get artifact generated by an analysis result for a previously
        submitted analysis task.

        :param str uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param str report_uuid: the unique report identifier returned as part of
            the dictionary returned by get_result().
        :param str artifact_name: the name of the artifact as mentioned in the
            given report in the dictionary returned by get_result().
        :param str password_protected: If provided, use this password to create a zip which will
            contain the artifact being fetched. The password provided should be using only
            ASCII characters and have max length of 128 characters
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :returns: A stream containing the artifact content
        :rtype: stream
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_file_download_url("analysis", ["get_report_artifact"])
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'artifact_name': artifact_name,
            'password_protected': password_protected,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })

        # NOTE: This API request is completely different because it
        # returns real HTTP status-codes (and errors) directly
        try:
            result = self._api_request(
                url,
                params,
                requested_format='raw',
                raw=True,
                verify=verify)
        except FailedRequestError as exc:
            status_code = str(exc.status_code())
            if status_code == '401':
                raise PermissionDeniedError("Permission denied to access artifacts")
            if status_code == '404':
                raise InvalidArtifactError(str(exc))
            if status_code == '410':
                raise InvalidArtifactError("The artifact is no longer available")
            if status_code == '412':
                raise InvalidUUIDError(str(exc))
            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

        return result

    def query_task_artifact(self, uuid, artifact_name, raw=False, verify=True,
                            allow_datacenter_redirect=None):
        """
        Query if a specific task artifact is available for download.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param artifact_name: the name of the artifact
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["query_task_artifact"])
        params = purge_none({
            'uuid': uuid,
            'artifact_name': artifact_name,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_ioc_metadata(self, ioc_uuid,
                         raw=False,
                         requested_format="json",
                         verify=True,
                         allow_datacenter_redirect=None):
        """
        Get metadata about a previously generated IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_ioc_metadata`.

        :param ioc_uuid: the unique identifier of the IOC, as returned by
            `get_results()`.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML.
            If format is not JSON, this implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['ioc', 'get_ioc_metadata'],
                               requested_format=requested_format)
        params = purge_none({
            'ioc_uuid': ioc_uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def get_ioc_report(self, ioc_uuid,
                       raw=False,
                       requested_format="json",
                       verify=True,
                       allow_datacenter_redirect=None):
        """
        Get an IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_ioc_report`.

        :param ioc_uuid: the unique identifier of the IOC, as returned by
            `get_results()`.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML.
            If format is not JSON, this implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['ioc', 'get_ioc_report'],
                               requested_format=requested_format)
        params = purge_none({
            'ioc_uuid': ioc_uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 verify=verify)

    def create_ioc_from_result(self,
                               uuid,
                               report_uuid=None,
                               raw=False,
                               requested_format="json",
                               verify=True,
                               report_version=None,
                               allow_datacenter_redirect=None):
        """
        Get an IOC report by its UUID.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.create_ioc_from_result`.

        :param uuid: the unique identifier of the task,
            as returned in the task_uuid field of submit methods.
        :param report_uuid: report from which to generated an IOC.
        :param requested_format: JSON, XML, or RAW.
            If format is not JSON, this implies `raw`.
        :param report_version: IOC format.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['ioc', 'create_ioc_from_result'],
                               requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'report_uuid': report_uuid,
            'report_version': report_version,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url,
                                 params,
                                 raw=raw,
                                 requested_format=requested_format,
                                 post=True,
                                 verify=verify)

    def get_network_iocs(self, uuid, raw=False, verify=True, allow_datacenter_redirect=None):
        """
        Get the network IOCs for an analysis task.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :type uuid: `str`
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: `bool`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :return: PCAP data containing IOC information.
        :rtype: list(PcapInfoV2)
        :raises InvalidAnalysisAPIResponse: If malscape response could not be parsed.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis",  ['ioc', 'get_network_iocs'])
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        response = self._api_request(url, params, raw=raw, verify=verify)
        if raw:
            return response
        network_ioc_response = []
        try:
            for network_ioc in response['data']['network_iocs']:
                if network_ioc['pcap_info_version'] != self.SUPPORTED_IOC_PCAP_VERSION:
                    raise InvalidAnalysisAPIResponse('malscape returns invalid pcap_info version')
                # version and url fields are required for pcap json decoding
                network_ioc['pcap_info']['version'] = self.SUPPORTED_IOC_PCAP_VERSION
                if 'urls' not in network_ioc['pcap_info']:
                    network_ioc['pcap_info']['urls'] = []
                try:
                    network_ioc_response.append(
                        llpcap_apiclient.PcapInfoV2.from_json({'data': network_ioc['pcap_info']})
                    )
                except llpcap_apiclient.Error as err:
                    raise InvalidAnalysisAPIResponse(
                        'malscape returns invalid network_ioc response: {}'.format(err))
        except KeyError as err:
            raise InvalidAnalysisAPIResponse(
                'malscape returns invalid network_ioc response: missing field {}'.format(err)
            )

        return network_ioc_response

    def completed(self, after, before=None, raw=False, verify=True):
        """
        *Deprecated*. Use 'get_completed()'
        """
        return self.get_completed(after, before=before,
                                  verify=verify, raw=raw)

    def get_completed(self, after, before=None, raw=False, verify=True,
                      include_score=False):
        """
        Get the list of uuids of tasks that were completed
        within a given time frame.

        The main use-case for this method is to periodically
        request a list of uuids completed since the last
        time this method was invoked, and then fetch
        each result with `get_result()`.

        Date parameters to this method can be:
         - date string: %Y-%m-%d'
         - datetime string: '%Y-%m-%d %H:%M:%S'
         - datetime.datetime object

        All times are in UTC.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_completed`.

        :param after: Request tasks completed after this time.
        :param before: Request tasks completed before this time.
        :param include_score: If True, the response contains scores together
            with the task-UUIDs that have completed
        :param raw: if True, return the raw JSON results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # better: use 'get_completed()' but that would break
        # backwards-compatibility
        url = self._build_url("analysis", ["completed"])
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)
        params = purge_none({
            'before': before,
            'after': after,
            'include_score': include_score and 1 or 0,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_completed_with_metadata(self, after, before=None, raw=False, verify=True):
        """
        Get the list of dictionaries, each containing a uuid for a task that was completed
        within a given time frame, the resulting score, and additional task_metadata

        The main use-case for this method is to periodically
        request a list of of dictionaries containing information about each task,
        such as the score and task_metadata. Then, additional information can be retrieved
        for a task with `get_result()`

        Date parameters to this method can be:
         - date string: %Y-%m-%d'
         - datetime string: '%Y-%m-%d %H:%M:%S'
         - datetime.datetime object

        All times are in UTC.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_completed_with_metadata`.

        :param after: Request tasks completed after this time.
        :param before: Request tasks completed before this time.
        :param raw: if True, return the raw JSON results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_completed_with_metadata"])
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)
        params = purge_none({
            'before': before,
            'after': after,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_pending(self, after=None, before=None, raw=False, verify=True):
        """
        Get the list of uuids of tasks that are pending (ie: not completed) within a given
        time frame.

        The main use-case for this method is for stateless clients to perform actions on
        pending tasks.

        Date parameters to this method can be:
         - date string: %Y-%m-%d'
         - datetime string: '%Y-%m-%d %H:%M:%S'
         - datetime.datetime object

        All times are in UTC.

        For return values and error codes please see
        :py:meth:`malscape_service.api.views.analysis.get_pending`.

        :param after: Request tasks completed after this time.
        :type after: `str` or `datetime.datetime`
        :param before: Request tasks completed before this time.
        :type before: `str` or `datetime.datetime`
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: `bool`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_pending"])
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)
        params = purge_none({'before': before, 'after': after})
        return self._api_request(url, params, raw=raw, verify=verify)

    def get_progress(self, uuid, raw=False, allow_datacenter_redirect=None):
        """
        Get a progress estimate for a previously submitted analysis task.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_results`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['get_progress'])
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def get_task_metadata(self, uuid, raw=False, allow_datacenter_redirect=None):
        """
        Get information about a task by its UUID.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_task_metadata`.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['get_task_metadata'])
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        return self._api_request(url, params, raw=raw)

    def export_report(self, uuid, report_type, report_format='PDF', raw=False):
        """
        Export a report or a combination of reports for a task.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.export_report`.

        :param str uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :param str report_type: The kind of report to generate. See
            `ANALYSIS_API_EXPORT_REPORT_TYPES` for supported types.
        :param str report_format: The output format. See
            `ANALYSIS_API_EXPORT_REPORT_FORMATS` for supported formats.
        :param bool raw: if True, return the raw JSON/XML results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        if report_type not in ANALYSIS_API_EXPORT_REPORT_TYPES:
            raise Error("Invalid report type")
        if report_format not in ANALYSIS_API_EXPORT_REPORT_FORMATS:
            raise Error("Invalid report format")
        url = self._build_url('analysis', ['export_report'])
        params = purge_none({
            'uuid': uuid,
            'report_type': report_type,
            'report_format': report_format,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def get_completed_exported_reports(self, resume_after_report_uuid=None, raw=False):
        """
        Get the available exported reports.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_completed_exported_reports`.

        :param str resume_after_report_uuid: The UUID of the last received report,
            we will provide reports generated *after* this one. If not provided, will start from
            the earliest stored ID.
        :param bool raw: if True, return the raw JSON/XML results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['get_completed_exported_reports'])
        params = purge_none({
            'resume_after_report_uuid': resume_after_report_uuid,
        })
        return self._api_request(url, params, raw=raw)

    def get_exported_report(self, exported_report_uuid):
        """
        Get an exported report.

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.get_exported_report`.

        :param str exported_report_uuid: The uuid of the exported report that we wish to return
        :returns: A stream containing the report content
        :rtype: stream
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code.
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_file_download_url('analysis', ['get_exported_report'])
        params = purge_none({
            'exported_report_uuid': exported_report_uuid,
            'cdn': self.__use_cdn
        })
        # NOTE: This API request returns real HTTP status-codes (and errors) directly
        try:
            response = self._api_request(url, params, raw=True, requested_format='raw')
            if isinstance(response, str):
                response = io.StringIO(response)
            return response
        except FailedRequestError as exc:
            status_code = str(exc.status_code())
            if status_code == '401':
                raise PermissionDeniedError("Permission denied to access artifacts")
            if status_code == '404':
                raise InvalidArtifactError(str(exc))
            if status_code == '410':
                raise InvalidArtifactError("The artifact is no longer available")
            if status_code == '412':
                raise InvalidUUIDError(str(exc))
            # we have nothing more specific to say -- raise the
            # original FailedRequestError
            raise

    def query_file_hash(self, hash_value=None, algorithm=None, block_size=None,
                        md5=None, sha1=None, sha256=None, mmh3=None, raw=False):
        """
        Search for existing analysis results with the given file-hash.

        :param hash_value: The (partial) file-hash.
        :param algorithm: One of MD5/SHA1/SHA256
        :param block_size: Size of the block (at file start) used for generating
            the hash-value. By default (or if 0), the entire file is assumed.
        :param md5: Helper to quickly set `hash_value` and `algorithm`
        :param sha1: Helper to quickly set `hash_value` and `algorithm`
        :param sha256: Helper to quickly set `hash_value` and `algorithm`
        :param mmh3: DEPRECATED! Don't use, mmh3 file hash is no longer supported
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this
            implies `raw`.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        if (mmh3 or (algorithm and algorithm.lower() == 'mmh3')) and self.__logger:
            self.__logger.warning(
                "No results will be returned for deprecated mmh3 file-hash query"
            )

        if md5 or sha1 or sha256 or mmh3:
            if hash_value or algorithm:
                raise TypeError("Conflicting values passed for hash/algorithm")
            if md5 and not sha1 and not sha256 and not mmh3:
                hash_value = md5
                algorithm = 'md5'
            elif sha1 and not md5 and not sha256 and not mmh3:
                hash_value = sha1
                algorithm = 'sha1'
            elif sha256 and not md5 and not sha1 and not mmh3:
                hash_value = sha256
                algorithm = 'sha256'
            elif mmh3 and not md5 and not sha1 and not sha256:
                hash_value = mmh3
                algorithm = 'mmh3'
            else:
                raise TypeError("Conflicting values passed for hash/algorithm")
        elif not hash_value or not algorithm:
            raise TypeError("Missing values for hash_value/algorithm")

        url = self._build_url('analysis', ['query/file_hash'])
        params = purge_none({
            'hash_value': hash_value,
            'hash_algorithm': algorithm,
            'hash_block_size': block_size,
        })
        return self._api_request(url, params, raw=raw)

    def is_blocked_file_hash(self, hash_value=None, algorithm=None,
                             block_size=None, md5=None, sha1=None, sha256=None,
                             mmh3=None, raw=False):
        """
        Check if the given file-hash belongs to a malicious file and we have
        gathered enough information to block based on this (partial) hash.

        :param hash_value: The (partial) file-hash.
        :param algorithm: One of MD5/SHA1/SHA256
        :param block_size: Size of the block (at file start) used for generating
            the hash-value. By default (or if 0), the entire file is assumed.
        :param md5: Helper to quickly set `hash_value` and `algorithm`
        :param sha1: Helper to quickly set `hash_value` and `algorithm`
        :param sha256: Helper to quickly set `hash_value` and `algorithm`
        :param mmh3: DEPRECATED! Don't use, mmh3 file hash is no longer supported
        :param raw: if True, return the raw JSON/XML results of the API query.
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        if (mmh3 or (algorithm and algorithm.lower() == 'mmh3')) and self.__logger:
            self.__logger.warning(
                "No results will be returned for deprecated mmh3 file-hash query"
            )

        if md5 or sha1 or sha256 or mmh3:
            if hash_value or algorithm:
                raise TypeError("Conflicting values passed for hash/algorithm")
            if md5 and not sha1 and not sha256 and not mmh3:
                hash_value = md5
                algorithm = 'md5'
            elif sha1 and not md5 and not sha256 and not mmh3:
                hash_value = sha1
                algorithm = 'sha1'
            elif sha256 and not md5 and not sha1 and not mmh3:
                hash_value = sha256
                algorithm = 'sha256'
            elif mmh3 and not md5 and not sha1 and not sha256:
                hash_value = mmh3
                algorithm = 'mmh3'
            else:
                raise TypeError("Conflicting values passed for hash/algorithm")
        elif not hash_value or not algorithm:
            raise TypeError("Missing values for hash_value/algorithm")

        url = self._build_url('analysis', ['query/is_blocked_file_hash'])
        params = purge_none({
            'hash_value': hash_value,
            'hash_algorithm': algorithm,
            'hash_block_size': block_size,
        })
        return self._api_request(url, params, raw=raw)

    def query_analysis_engine_tasks(self, analysis_engine_task_uuids,
                                    analysis_engine='analyst', raw=False):
        """
        Provide a set of task UUIDs from an analysis engine (such as Analyst
        Scheduler or Anubis) and find completed tasks that contain this analysis
        engine task.

        THIS FUNCTION IS DEPRECATED - DO NOT USE!
        """
        url = self._build_url('analysis', ['query/analysis_engine_tasks'])
        params = purge_none({
            'analysis_engine_task_uuids': ','.join(analysis_engine_task_uuids),
            'analysis_engine': analysis_engine,
        })
        return self._api_request(url, params, raw=raw)

    def analyze_sandbox_result(self, analysis_task_uuid,
                               analysis_engine='anubis',
                               full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                               bypass_cache=False,
                               raw=False,
                               allow_datacenter_redirect=None):
        """
        Provide a task UUID from an analysis engine (such as Analyst Scheduler
        or Anubis) and trigger scoring of the activity captured by the analysis
        report.

        Similar to submitting by exe hash (md5/sha1/sha256) but we can enforce
        the precise analysis result (if there are multiple) that we want
        to score

        For return values and error codes please
        see :py:meth:`malscape_service.api.views.analysis.analyze_sandbox_result`.

        Requires specific permissions.

        :param analysis_task_uuid: The sandbox task UUID to analyze/import.
                                   Lastline-internal/do not use.
        :param analysis_engine: The sandbox the task refers to.
                                Lastline-internal/do not use.
        :param full_report_score: if set, this value (between -1 and 101)
            determines starting at which scores a full report is returned.
            -1 and 101 indicate "never return full report";
            0 indicates "return full report at all times"
        :param bypass_cache: if True, the API will not serve a cached
            result. NOTE: This requires special privileges.
        :param raw: if True, return the raw JSON results of the API query.
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('analysis', ['analyze_sandbox_result'])
        params = purge_none({
            'analysis_task_uuid':analysis_task_uuid,
            'analysis_engine': analysis_engine,
            'full_report_score': full_report_score,
            'bypass_cache': bypass_cache and 1 or 0,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        purge_none(params)
        return self._api_request(url, params, raw=raw)

    def register_completion(self, uuid, force_register=True, raw=False):
        """
        Register submission of a given task_uuid to the user that is authenticated

        :param uuid: the unique identifier of the submitted task, as returned in the task_uuid
            field of submit methods.
        :type uuid: `str`
        :param force_register: If set to True indicate that we should create a submission even if
            we already have one in place for the same license/task-uuid. If False, don't create a
            new one unless needed
        :type force_register: `bool`
        :returns: Dictionary with information regarding if registered task is already completed
            or not
        :rtype: `dict`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["register_completion"])
        params = purge_none({
            'uuid': uuid,
            'force_register': force_register and 1 or 0,
        })
        return self._api_request(url, params, post=True, raw=raw)

    def get_analysis_tags(self, uuid, raw=False, verify=True, allow_datacenter_redirect=None,
                          requested_format="json"):
        """
        Get the analysis tags for an analysis task.

        :param uuid: the unique identifier of the submitted task,
            as returned in the task_uuid field of submit methods.
        :type uuid: `str`
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: `bool`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :type allow_datacenter_redirect: `bool`
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :type requested_format: `str`
        :return: Dictionary of analysis tag data
        :rtype `dict`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_analysis_tags"], requested_format=requested_format)
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        if requested_format.lower() != 'json':
            raw = True
        return self._api_request(url, params, raw=raw, verify=verify,
                                 requested_format=requested_format)

    def get_child_tasks_recursively(self, uuid, raw=False, verify=True,
                                    allow_datacenter_redirect=None):
        """
        Get all the child tasks recursively for the given task UUID.

        :param uuid: The task UUID
        :type uuid: str
        :param raw: if True, return the raw JSON results of the API query.
        :type raw: bool
        :param verify: if False, disable SSL-certificate verification
        :type verify: bool
        :param allow_datacenter_redirect: If False, redirection to other datacenters prevented.
        :return: The child tasks UUID and their information. The result will be returned
            in dict type with the child task UUID as the key and the depth data as
            the value

            Example:
                { 'task_uuid': 'ffffffffffffffff',
                  'child_tasks':
                        {
                            'aaaaaaaa': {'depth': 1},
                            'bbbbbbbb': {'depth': 2},
                        }
                }

        :rtype: dict(dict)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url("analysis", ["get_child_tasks_recursively"])
        params = purge_none({
            'uuid': uuid,
            'allow_datacenter_redirect': allow_datacenter_redirect,
        })
        return self._api_request(url, params, raw=raw, verify=verify)

    def update_global_whitelist_info(
        self, uploader_name, create_uploader=False, md5=None, sha1=None, sha256=None,
        confidence=None, is_revoked=False, is_public=False, raw=False
    ):
        """
        Update global whitelist database with file information

        :param uploader_name: The name of the global whitelist uploader
        :type uploader_name: str
        :param create_uploader: True if the uploader name associated with this whitelist update
            (usually user email) should be created in whitelist DB if not already present.
        :type create_uploader: bool
        :param md5: The MD5 hash of the data to query
        :type md5: str
        :param sha1: The SHA1 hash of the data to query
        :type sha1: str
        :param sha256: The SHA256 hash of the data to query
        :type sha256: str
        :param confidence: confidence rating of this whitelist entry (1-100). If None, will
        use default confidence of the uploader.
        :type confidence: int
        :param is_revoked: True if this file is no longer whitelisted.
        :type is_revoked: bool
        :param is_public: True if this whitelist entry may be made publicly available to Lastline
        customers.
        :type is_public: bool
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        assert md5 or sha1 or sha256, "Need to provide one of md5/sha1/sha256"

        url = self._build_url('management', ['update_global_whitelist_info'])
        params = purge_none({
            'uploader_name': uploader_name,
            'create_uploader': create_uploader,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'confidence': confidence,
            'is_revoked': is_revoked,
            'is_public': is_public
        })

        return self._api_request(url, params, post=True, raw=raw)

    def add_untrusted_signer(
        self, signer_name, reputation, regexp_common_name=None, regexp_company_name=None, raw=False
    ):
        """
        Add untrusted signer information with negative reputation to database

        :param str signer_name: A name identification for the trusted_signer
        :param int reputation: The reputation to be assigned to the trusted signer
        :param str | None regexp_common_name: The regexp to be applied to identify the
            trusted signer
        :param str | None regexp_company_name:  If present, contains a regular expression
            to match the company name
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['add_untrusted_signer'])

        if not (-100 <= reputation < 0):
            raise Error("Invalid reputation value")

        params = purge_none({
            'signer_name': signer_name,
            'regexp_common_name': regexp_common_name,
            'reputation': reputation,
            'regexp_company_name': regexp_company_name
        })

        return self._api_request(url, params, post=True, raw=raw)

    def add_trusted_signer(
        self, signer_name, reputation, file_stream, hash_type='sha1',
        regexp_common_name=None, regexp_company_name=None, raw=False
    ):
        """
        Adding trusted signer fingerprint to the database

        :param str signer_name: A name identification for the trusted_signer
        :param int reputation: The reputation to be assigned to the trusted signer
        :param stream file_stream: Stream to submit
        :param str regexp_common_name: The regexp to be applied to identify the
            trusted signer
        :param str | None regexp_company_name:  If present, contains a regular expression
            to match the company name
        :param str hash_type: Hash algorithm used to generate the certificate fingerprint.
            Currently accept 'md5' and 'sha1'
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['add_trusted_signer'])

        if not (0 <= reputation <= 100):
            raise Error("Invalid reputation value")

        if hash_type not in frozenset(['md5', 'sha1']):
            raise Error("Invalid hash type: {}".format(hash_type))

        params = purge_none({
            'signer_name': signer_name,
            'reputation': reputation,
            'regexp_common_name': regexp_common_name,
            'regexp_company_name': regexp_company_name,
            'hash_type': hash_type
        })

        files = {"file": ('file', file_stream)}

        return self._api_request(url, params, files=files, post=True, raw=raw)

    def remove_signer_fingerprint(self, md5_fingerprint=None, sha1_fingerprint=None, raw=False):
        """
        Removing a signer fingerprint from the database. Caller must provide only one of
        md5_fingerprint or sha1_fingerprint parameters

        :param str | None md5_fingerprint: The md5 hash value of the fingerprint
        :param str | None sha1_fingerprint:  The sha1 hash value of the fingerprint
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['remove_signer_fingerprint'])

        if not md5_fingerprint and not sha1_fingerprint:
            raise Error("Please provide either md5 or sha1 fingerprint")

        if md5_fingerprint and sha1_fingerprint:
            raise Error("Please don't provide both md5 and sha1 fingerprint")

        params = purge_none({
            'md5_fingerprint': md5_fingerprint,
            'sha1_fingerprint': sha1_fingerprint
        })

        return self._api_request(url, params, post=True, raw=raw)

    def remove_signer(self, signer_name, raw=False):
        """
        Removing a signer from the database. Note: Signer cannot be removed if there remains a
        signer fingerprint associated with it.

        :param str signer_name: The name of the signer
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['remove_signer'])

        assert signer_name, "Signer name cannot be empty"

        params = {'signer_name': signer_name}

        return self._api_request(url, params, post=True, raw=raw)

    def get_mitre_attack_info(
        self, mitre_technique_ids=None, mitre_tactic_ids=None, raw=False, verify=True
    ):
        """
        From a list of mitre technique or tactic ids, get the information for each ID passed in

        :param list(str) mitre_technique_ids: A list of Mitre technique IDs
        :param list(str) mitre_tactic_ids: A list of Mitre tactic IDs
        :return: The dictionary with a mapping of each ID passed in (if we know info about it)
            and the info for that ID

            Example:
                {
                    'mitre_techniques': {
                        'ID1':
                            {
                                'name': 'foo',
                                'id': 'ID1',
                                'description': 'id1 description',
                                'url': 'https://attack.mitre.org/techniques/ID1',
                                'tactics': [
                                    {
                                        'id': 'tactic1',
                                        'name': 'bar',
                                        'description': 'tactic1 description',
                                        'url': 'https://attack.mitre.org/tactics/tactic1',
                                    },
                                    {
                                        'id': 'tactic2',
                                        'name': 'bar2',
                                        'description': 'tactic2 description',
                                        'url': 'https://attack.mitre.org/tactics/tactic2',
                                    },
                                ]
                            }
                        }
                    },
                    'mitre_tactics': {
                        'ID2': {
                            'id': 'id2',
                            'name': 'bar3',
                            'description': 'id2 description',
                            'url': 'https://attack.mitre.org/tactics/id2',
                        }
                    }

        :rtype: dict(dict)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        assert mitre_technique_ids or mitre_tactic_ids, 'Missing mitre_technique and tactics ids'
        url = self._build_url("analysis", ["get_mitre_attack_info"])
        params = {}
        if mitre_technique_ids:
            params['mitre_technique_ids'] = ','.join(mitre_technique_ids)
        if mitre_tactic_ids:
            params['mitre_tactic_ids'] =  ','.join(mitre_tactic_ids)
        return self._api_request(url, params, raw=raw, verify=verify)

    def add_av_detection_score(
        self, av_product_name, llfile_class_name, av_class_name=None, av_family_name=None,
        score=None,
    ):
        """
        Add an av detection score suppressor entry in the DB

        :param str av_product_name: The name of the av product we want to apply the suppression to
        :param str llfile_class_name: The llfile class name we want to apply the suppression to,
            for example 'File' or 'DosExeFile'. This should be the exact same name of the
            llfile class that will be suppressed.
        :param str av_class_name: If provided, only add suppression for the passed av class,
            for example 'trojan'. This should be the exact class name that we are using when doing
            the suppression of the sample. If None is provided, we will look on the other filters
            for doing the suppression (llfile_class/av_family_name)
        :param str av_family_name: If provided, only add suppression for the passed av family,
            for example 'manilla'. This should be the exact family name that we are using when
            doing the suppression of the sample. If None is provided, we will look on the other
            filters for doing the suppression (llfile_class/av_class_name)
        :param int score: If provided, when suppressing the detection score, set this score
            instead. If not provided, we will always set the score 0
        :return: A dictionary with information about the addition of the suppression in the
            database, for example:
                If update successfully

                {
                    'updated': True,
                    'message': 'Av detection score has been added or updated'
                }

                If update failed

                {
                    'updated': False,
                    'message': 'Score is not in a valid range'
                }
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['add_av_detection_score'])

        if score is not None and not (0 <= score <= 100):
            raise Error("Invalid score value")


        params = purge_none({
            'av_product_name': av_product_name,
            'llfile_class_name': llfile_class_name,
            'av_class_name': av_class_name,
            'av_family_name': av_family_name,
            'score': score
        })
        return self._api_request(url, params, post=True)

    def delete_av_detection_score(
        self, av_product_name, llfile_class_name, av_class_name=None, av_family_name=None
    ):
        """
        Remove an av detection score suppressor entry in the DB

        :param str av_product_name: The name of the av product in the entry we want to delete
        :param str llfile_class_name: The llfile class name in the entry we want to delete,
            for example 'File' or 'DosExeFile'. This should be the exact same name of the
            llfile class that was stored before, when doing the suppression
        :param str av_class_name: If provided, only delete the entry with this av_class,
            for example 'trojan'. This should be the exact class name that was used when creating
            the suppression earlier.
        :param str av_family_name: If provided, only delete the entry with this av_family,
            for example 'manilla'. This should be the exact family name that was used when creating
            the suppression earlier.
        :return: A dictionary with information about the deletion of the suppression in the
            database, for example:
                If update successfully
                {
                    'removed': True,
                    'message': 'Av detection has been removed'
                }

                If update failed

                {
                    'removed': False,
                    'message': 'Removing av detection failed, nothing changed'
                }
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['delete_av_detection_score'])

        params = purge_none({
            'av_product_name': av_product_name,
            'llfile_class_name': llfile_class_name,
            'av_class_name': av_class_name,
            'av_family_name': av_family_name,
        })
        return self._api_request(url, params, post=True)

    def _api_request(self,
                     url,
                     params=None,
                     files=None,
                     timeout=None,
                     post=False,
                     raw=False,
                     requested_format="json",
                     verify=True):
        """
        Send an API request and return the results.

        :param url: API URL to fetch.
        :param params: GET or POST parameters.
        :param files: files to upload with request.
        :param timeout: request timeout in seconds.
        :param post: use HTTP POST instead of GET
        :param raw: return the raw json results of API query
        :param requested_format: JSON or XML. If format is not JSON, this implies `raw`.
        :param verify: if True, verify ssl, otherwise False
        """
        raise NotImplementedError("%s does not implement api_request()" % self.__class__.__name__)

    def _process_response_page(self, page, raw, requested_format, disposition=None):
        """
        Helper for formatting/processing api response before returning it.
        """
        if raw or requested_format.lower() != "json":

            # Handle special dispositions
            if disposition:
                disp_type = disposition.get('type')
                disp_params = disposition.get('params')

                if disp_type == 'attachment':
                    return NamedStringIO(
                        page, name=disp_params.get('filename'))

            return page

        #why does pylint think result is a bool??
        #pylint: disable=E1103
        result = simplejson.loads(page)
        success = result['success']
        if success:
            return result

        error_code = result.get('error_code', None)
        # raise the most specific error we can
        exception_class = AnalysisClientBase.ERRORS.get(error_code, AnalysisAPIError)
        raise exception_class(result['error'], error_code)

    def rescore_task(self, md5, sha1,
                     min_score=0, max_score=100,
                     threat=None, threat_class=None,
                     uploader_name='malscape-rescoring',
                     create_uploader=False,
                     force_local=False, raw=False):
        """
        Enforce re-scoring of a specific file based on the
        submitted file's md5/sha1 hash. Requires specific permissions.

        md5 and sha1 must be provided. sha1 must
        match with the md5 that was provided. Existing manual-score threat/
        threat-class information will not be overwritten unless an empty-
        string ('') is passed to this function.

        This API-call returns the task-UUIDs that were triggered for rescoring.

        :param md5: the md5 hash of the submitted file.
        :param sha1: the sha1 hash of the submitted file.
        :param uploader_name: The name of the uploader (usually user email) to put into the global
            whitelist database.
        :type uploader_name: str
        :param create_uploader: True if the uploader name associated with this whitelist update
             should be created in whitelist DB if not already present.
        :type create_uploader: bool
        :param force_local: if True, enforce that the manual score is applied
            only locally. This is the default for on-premise instances and
            cannot be enforced there. Requires special permissions.
        :param raw: if True, return the raw JSON/XML results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        assert md5 and sha1, "Please provide md5 and sha1"
        url = self._build_url('management', ['rescore'])
        params = purge_none({
            'md5': md5,
            'sha1': sha1,
            'min_score': min_score,
            'max_score': max_score,
            'threat': threat,
            'threat_class': threat_class,
            'uploader_name': uploader_name,
            'create_uploader': create_uploader,
            # use the default if no force is set
            'force_local': force_local and 1 or None,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def rescore_backend_task(self, report_uuid, score=None, reputation=None, raw=False):
        """
        Enforce re-scoring of a specific backend task using the new score/reputation.

        One of score/reputation must be provided, as appropriate to the backend type.
        Alternatively, if no score or reputation is provided the task associated with the
        backend task is rescored without changing the backend task score.

        :param str report_uuid: the unique identifier of the backend task, as returned in the
             report_uuid field of get_task_status method for each backend engaged in the task.
        :param int score: the new score of the backend task, for backend tasks with a score column.
        :param int reputation: the new reputation of the backend task, for backend tasks with a
            reputation column.
        :param bool raw: if True, return the raw JSON/XML results of the API query.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        assert report_uuid is not None, "Please provide report_uuid"
        assert score is None or reputation is None, "Please provide only ONE of score/reputation"

        url = self._build_url('management', ['rescore_backend'])
        params = purge_none({
            'report_uuid': report_uuid,
            'score': score,
            'reputation': reputation,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def rescore_scanner(self, scanner, after, before,
                         min_score=0, max_score=100,
                         min_scanner_score=0, max_scanner_score=100,
                         min_version=0, max_version=None,
                         test_flag=None, force=False,
                         raw=False):
        """
        Find tasks that triggered a certain scanner and mark them for
        reprocessing.

        This API-call returns the task-UUIDs that were triggered for rescoring.

        :param scanner: Name of the scanner.
        :param after: Reprocess tasks completed after this time.
        :param before: Reprocess tasks completed before this time.
        :param min_score: Minimum score of tasks to reprocess.
        :param max_score: Maximum score of tasks to reprocess.
        :param min_scanner_score: Minimum score of scanner detection (on backend
            task) to reprocess.
        :param max_scanner_score: Maximum score of scanner detection (on backend
            task) to reprocess.
        :param min_version: Minimum version of scanner to reprocess.
        :param max_version: Maximum version of scanner to reprocess.
        :param test_flag: If True, only affect backend-tasks where the scanner
            was in *test* mode; if False, only affect backend-tasks where the
            scanner was in *real* mode; otherwise affect all backend-tasks
            regardless of the *test* flag.
        :param force: By default, the API will refuse rescoring any scanners that
            affect more than 100 tasks. To rescore large amounts, distribute the
            work over multiple time-windows. This safety can be disabled by
            setting the *force* parameter to True.
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        if hasattr(before, "strftime"):
            before = before.strftime(AnalysisClientBase.DATETIME_FMT)
        if hasattr(after, "strftime"):
            after = after.strftime(AnalysisClientBase.DATETIME_FMT)

        url = self._build_url('management', ['rescore_scanner'])
        params = purge_none({
            'scanner': scanner,
            'after': after,
            'before': before,
            'min_score': min_score,
            'max_score': max_score,
            'min_scanner_score': min_scanner_score,
            'max_scanner_score': max_scanner_score,
            'min_version': min_version,
            'max_version': max_version,
        })
        if test_flag is not None:
            params['test_flag'] = test_flag and 1 or 0
        if force:
            params['force'] = 1
        return self._api_request(url, params, raw=raw, post=True)

    def suppress_scanner(self, scanner, max_version, raw=False):
        """
        Mark a scanner as suppressed.

        :param scanner: Name of the scanner.
        :param max_version: Version of scanner up to which it is supposed to be
            suppressed. So, if the first scanner-version that should be used
            for scoring is X, provide (X-1).
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        url = self._build_url('management', ['suppress_scanner'])
        params = purge_none({
            'scanner': scanner,
            'max_version': max_version,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def create_ticket(self, uuid=None, md5=None, sha1=None,
                      min_score=0, max_score=100, summary=None, labels=None,
                      is_false_negative=False, is_false_positive=False,
                      is_from_customer=False, is_from_partner=False,
                      is_falses_ml=False, force=True, raw=False):
        """
        Create an ANREV ticket for a specific task or multiple tasks based on
        the submitted file. Requires specific permissions.

        At least one of uuid/md5/sha1 must be provided. If both file-hashes are
        provided, they must match the same file.

        :param str uuid: the unique identifier of the submitted task, as returned in the task_uuid
            field of submit methods.
        :param str md5: the md5 hash of the submitted file.
        :param str sha1: the sha1 hash of the submitted file.
        :param bool force: if True, enforce the generation of a ticket, even if none  of the
            task-analysis rules would have generated a ticket
        :param int min_score: Limit generation of tickets to tasks above the given threshold
        :param int max_score: Limit generation of tickets to tasks below the given threshold
        :param str summary: Optional summary (title) to use for the ticket.
        :param iterable[str] labels: Optional set of labels to assign to a task
        :param bool is_false_negative: Helper parameter to add the standard FN label
        :param bool is_false_positive: Helper parameter to add the standard FP label
        :param bool is_from_customer: Helper parameter to add the standard from-customer label
        :param bool is_from_partner: Helper parameter to add the standard from-partner label
        :param bool is_falses_ml: Helper parameter to add the standard falses-ml label
        :param bool raw: if True, return the raw JSON/XML results of the API query.
        :returns: a dictionary detailing the result.
            - If successful a dictionary with at least the following keys:
                - result: the result of the action
                - task_uuid: the task uuid of the analysis
                - score: the score given to that analysis
            - If the outcome includes the creation of a ticket, then the following keys are added:
                - ticket_id: the (internal) Jira id of the ticket
                - ticket_key: the (public) Jira key of the ticket
                - ticket_url: the URL of the ticket

        Examples:
            - Creating a ticket about a false positive from a customer:

                analysis.create_ticket(
                    md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    is_false_positive=True,
                    is_from_customer=True
                )

            - Content of a successful response:

                {
                    "result": "Ticket generated",
                    "task_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "score": 66,
                    "ticket_id": "123",
                    "ticket_key": "ANREV-333",
                    "ticket_url": "https://lastline.atlassian.net/browse/ANREV-333"
                }
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        assert uuid or md5 or sha1, "Please provide task-uuid/md5/sha1"
        url = self._build_url('management', ['create_ticket'])
        if labels:
            labels = set(labels)
        else:
            labels = set()
        if is_false_negative:
            labels.add('false_negatives')
        if is_false_positive:
            labels.add('false_positives')
        if is_from_customer:
            labels.add('from-customer')
        if is_from_partner:
            labels.add('from-partner')
        if is_falses_ml:
            labels.add('falses-ml')
        if labels:
            labels_list = ','.join(labels)
        else:
            labels_list = None
        params = purge_none({
            'uuid': uuid,
            'md5': md5,
            'sha1': sha1,
            'min_score': min_score,
            'max_score': max_score,
            'force': force and 1 or 0,
            'summary': summary,
            'labels': labels_list,
        })
        return self._api_request(url, params, raw=raw, post=True)

    def get_license_activity(self, query_start=None, query_end=None,
                             raw=False):
        """
        Fetch license activity information.

        DEPRECATED. DO NOT USE
        """
        unused = query_start, query_end, raw
        assert False, "Call to deprecated API function"

    def get_api_utc_timestamp(self):
        """
        Query the API to get its UTC timestamp: do this *before* submitting
        to avoid racing or clock-skew with the local clock

        :returns: Current UTC timestamp according to API
        :rtype: `datetime.datetime`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        start_info = self.get_completed(
            after='2039-12-31 23:59:59'
        )
        return parse_datetime(start_info['data']['before'])

    def get_status(self):
        """
        Get the status of malscape, indicating if all is ok or not

        :param raw: if True, return the raw JSON results of the API query.
        :returns: A dict with the load results:
            {
                'all_ok': An int which can be 0 or 1 indicating that everything is ok (1) or if
                    something is not correct (0) in malscape
            }
        """
        url = self._build_url('management', ['get_status'])
        return self._api_request(url)

    def ping(self, raw=False, verify=True):
        """
        Check if base API responds.
        """
        url = self._build_url('authentication', ['ping'])
        return self._api_request(url, raw=raw, verify=verify)

    def is_risky_analysis_artifact(self,
                                   report_uuid,
                                   artifact_name,
                                   task_uuid=None,
                                   raw=False,
                                   verify=True,
                                   allow_datacenter_redirect=None):
        """
        Check if the artifact can potentially be malicious using the artifact information.

        :param str report_uuid: Identifier of the requested report to which the artifact is assigned
        :param str artifact_name: Identifier of task artifact
        :param str|None task_uuid: Unique identifier for the task that analyzed the artifact. If not
            present, will only look for artifact in local datacenter.
        :param bool raw: if True, return the raw JSON results of the API query.
        :param bool verify: if True, verify ssl, otherwise False
        :param bool|None allow_datacenter_redirect: If False, redirection to other datacenters
            prevented.
        :return: True if the artifact is risky, False otherwise
        :rtype: bool
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        :raises InvalidArtifactError: Invalid artifact uuid.
        """

        if report_uuid and artifact_name:
            params = purge_none({
                'artifact_uuid': "{}:{}".format(report_uuid, artifact_name),
                'uuid': task_uuid,
                'allow_datacenter_redirect': allow_datacenter_redirect,
            })
            url = self._build_url('analysis', ['is_risky_analysis_artifact'])
            return self._api_request(url, params, raw=raw, verify=verify)
        raise InvalidArtifactError("The report uuid and artifact name must both be provided")


class AnalysisClient(AnalysisClientBase):
    """
    Client for the Analysis API.

    A client for the Analysis API that accesses the API through the web,
    using key and api token for authentication, and the python
    requests module for sending requests.

    NOTE: This class is not thread safe
    """

    # maximum unsuccessful login attempts in a row
    MAX_LOGIN_ATTEMPTS = 2

    DEFAULT_TIMEOUT = 60

    _AUTH_METHOD__LICENSE = 'license'
    _AUTH_METHOD__UNAUTHENTICATED = 'unauthenticated'
    _AUTH_METHODS = (_AUTH_METHOD__LICENSE, _AUTH_METHOD__UNAUTHENTICATED)

    @classmethod
    def from_config(cls, config, config_section='analysis', logger=None):
        """
        Factory method for instantiating an API client from config

        :param ConfigParser.ConfigParser config: Config object to rad from
        :param str config_section: Section to read from
        :param logging.Logger logger: Logger to use for API client instance
        :return AnalysisClient: Instantiated client
        :raise ConfigParser.Error: The provided configuration is invalid or incomplete
        :raise ValueError: The provided configuration contains incorrect types for values
        """
        auth_method = cls._AUTH_METHOD__LICENSE
        try:
            auth_method = config.get(config_section, 'auth_method')
        except configparser.NoOptionError:
            pass  # keep default
        else:
            if auth_method not in cls._AUTH_METHODS:
                raise ValueError("Unsupported auth_method '{}'".format(auth_method))

        try:
            verify_ssl = config.getboolean(config_section, 'verify_ssl')
        except configparser.NoOptionError:
            verify_ssl = True

        try:
            timeout = config.getfloat(config_section, 'timeout')
        except configparser.NoOptionError:
            timeout = AnalysisClient.DEFAULT_TIMEOUT

        key = None
        api_token = None
        if auth_method == cls._AUTH_METHOD__LICENSE:
            key = config.get(config_section, 'key')
            try:
                api_token = config.get(config_section, 'api_token')
            except configparser.NoOptionError:
                pass  # for sensor-licenses, the API-token is optional

        try:
            use_cdn = config.getboolean(config_section, 'use_cdn')
        except configparser.NoOptionError:
            use_cdn = None

        return cls(
            base_url=config.get(config_section, 'url'),
            key=key,
            api_token=api_token,
            verify_ssl=verify_ssl,
            timeout=timeout,
            use_cdn=use_cdn,
            logger=logger,
            config=config,
        )

    def __init__(
        self,
        base_url,
        key,
        api_token,
        logger=None,
        ca_bundle=None,
        verify_ssl=True,
        use_curl=False,
        timeout=DEFAULT_TIMEOUT,
        use_cdn=None,
        proxies=None,
        config=None
    ):
        """
        :param str base_url: URL where the lastline analysis API is located. (required)
        :param str|None key: API key for the Lastline Analyst API. If None is provided, the
            client will not embed any type of authentication assuming an upstream proxy will
            embed the required credentials
        :param str|None api_token: Optional API token for the Lastline Analyst API to embed.
            The API token is optional for certain types of authentication schemas and may be
            omitted
        :param logging.Logger|None logger: if provided, should be a python logging.Logger object
            or object with similar interface.
        :param object|None ca_bundle: if provided, location of Certification Authority bundle
            to use for authentication. This should not be required
            if certificates are properly setup on the system.
        :param bool verify_ssl: if True, verify SSL certificates. This overrides the
            per-call parameter
        :param dict proxies: dictionary with per-protocol proxy to use to use
            (e.g. { 'http': 'localhost:3128', 'https': 'localhost:3128' }
        :param float timeout: default timeout (in seconds) to use for network requests.
            Set to None to disable timeouts
        :param bool use_cdn: If False, will return CDN eligible content directly. Otherwise, will
            use the CDN to deliver the content.
        """
        AnalysisClientBase.__init__(self, base_url, use_cdn, logger, config)
        self.__key = key
        self.__api_token = api_token
        self.__ca_bundle = ca_bundle
        self.__verify_ssl = verify_ssl
        self.__logger = logger
        self.__timeout = timeout
        if use_curl and logger:
            logger.warning("Ignoring deprecated use_curl option")
        if proxies is None and config:
            self.__proxies = get_proxies_from_config(config)
        else:
            self.__proxies = proxies
        self.__session = None

    def set_key(self, key):
        self.__key = key
        self._logout()

    def set_api_token(self, api_token):
        self.__api_token = api_token
        self._logout()

    def set_ssl_verification(self, value=True):
        """
        Allow enabling/disabling SSL verification on the fly
        """
        self.__verify_ssl = value

    def _login(self):
        """
        Creates auth session for malscape-service.
        """
        # if the client runs in a mode without authentication, building a session
        # and doing an explicit login is not necessary.
        if self.__key is None:
            self.__session = MockSession(logger=self._logger())
            return

        self.__session = requests.session()
        url = self._build_url('authentication', ['login'])
        params = {'key': self.__key}
        if self.__api_token:
            params['api_token'] = self.__api_token
        try:
            self._api_request(url=url, params=params, post=True, verify=self.__verify_ssl)
        except FailedRequestError as exc:
            if exc.status_code() != 404:
                raise
            if self._logger():
                self._logger().debug("Login raised %s: switching to legacy authentication", exc)
            # the API does not support the login call, and thus not session-based authentication.
            # Switch to embedding credentials in each request
            self.__session = MockSession(credentials=params, logger=self._logger())

    def _logout(self):
        """
        Destroys auth session for malscape-service.
        """
        if not self.__session:
            return
        self.__session.close()
        self.__session = None

    def _save_stream_positions(self, files):
        """
        Stores stream_positions for files

        :param files: dictionary with filestreams, according to requests.request 'files' parameter
        :type files: `dict`
        :return: dictionary with filenames and according stream positions
        :rtype: `dict`
        """
        result = {}
        if not files:
            return result
        for file_name, file_object in files.items():
            # 'files' value can be tuple or file-like object, according to python-requests docs
            if isinstance(file_object, tuple):
                file_stream = file_object[1]
            else:
                file_stream = file_object
            result[file_name] = file_stream.tell()
        return result

    def _restore_stream_positions(self, stream_positions, files):
        """
        Restores stream positions, saved earlier

        :param stream_positions: dictionary 'filename: position'
        :type stream_positions: `dict`
        :param files: dictionary with filestreams, according to requests.request 'files' parameter
        :type files: `dict`
        """
        for file_name, stream_position in stream_positions.items():
            file_object = files[file_name]
            if isinstance(file_object, tuple):
                file_stream = file_object[1]
            else:
                file_stream = file_object
            file_stream.seek(stream_position)

    def _api_request(self,
                     url,
                     params=None,
                     files=None,
                     timeout=None,
                     post=False,
                     raw=False,
                     requested_format="json",
                     verify=True):
        # first, perform authentication, if we have no session
        if not self.__session:
            self._login()

        if self._logger():
            self._logger().info("Requesting %s" % url)
        if not params:
            params = {}

        # we allow anyone setting this flag, but only admins will get any data back
        if self.REQUEST_PERFDATA:
            params['perfdata'] = 1

        method = "GET"
        data = None
        if post or files:
            method = "POST"
            data = params
            params = None

        if not self.__verify_ssl or not verify:
            verify_ca_bundle = False
        elif self.__ca_bundle:
            verify_ca_bundle = self.__ca_bundle
        else:
            verify_ca_bundle = True

        # save stream positions in case of reauthentication
        stream_positions = self._save_stream_positions(files)
        # start authentication / reauthentication loop
        login_attempt = 1
        while True:
            try:
                response = self.__session.request(
                    method, url,
                    params=params, data=data, files=files,
                    timeout=timeout or self.__timeout,
                    verify=verify_ca_bundle,
                    proxies=self.__proxies)
                # raise if anything went wrong
                response.raise_for_status()

            except requests.HTTPError as exc:
                if self.__logger:
                    self.__logger.warning("HTTP Error contacting Lastline Analyst API: %s", exc)
                if exc.response is not None:
                    status_code = exc.response.status_code
                    msg = exc.response.text
                else:
                    status_code = None
                    msg = None
                # raise a wrapped exception - if the HTTP status code maps into a specific
                # exception class, use that class
                try:
                    exception_class = AnalysisClientBase.HTTP_ERRORS[status_code]
                except KeyError:
                    raise FailedRequestError(msg=msg, error=exc, status_code=status_code)
                else:
                    raise exception_class(msg=msg)

            except requests.RequestException as exc:
                if self.__logger:
                    self.__logger.warning("Error contacting Lastline Analyst API: %s", exc)
                # raise a wrapped exception
                raise CommunicationError(error=exc)

            # Get the response content, as a unicode string if the response is
            # textual, as a regular string otherwise.
            content_type = response.headers.get("content-type")
            if content_type and (
                        content_type.startswith("application/json") or
                        content_type.startswith("text/")):
                response_data = response.text
            else:
                response_data = response.content

            # Get the response disposition if defined
            disposition = None
            content_disposition = response.headers.get("content-disposition")
            if content_disposition:
                # Always returns a couple type, params even if
                # no parameters are provided or the string is empty
                disp_type, disp_params = cgi.parse_header(content_disposition)
                if disp_type:
                    disposition = {'type': disp_type.lower(),
                                   'params': disp_params}

            try:
                response_result = self._process_response_page(
                    response_data, raw, requested_format, disposition
                )
            except AuthenticationError:
                self._logout()

                # if this is not a real session, we have embedded the credentials in the request
                # and retrying won't change anything
                if isinstance(self.__session, MockSession):
                    raise

                # don't try more than N times - we essentially need to only retry establishing a
                # session, so N>2 doesn't make too much sense
                if login_attempt >= self.MAX_LOGIN_ATTEMPTS:
                    raise AuthenticationError(
                        'login failed for {} times'.format(self.MAX_LOGIN_ATTEMPTS))

                if self.__logger:
                    self.__logger.warning('attempting to restore connection for %d time',
                                          login_attempt)
                self._login()
                self._restore_stream_positions(stream_positions, files)
                login_attempt += 1
            else:
                # if all goes well, just return result
                return response_result


class SubmittedTask(object):
    """
    Representation of a task that was submitted
    """
    def __init__(self, task_uuid, score=None, error=None, error_exception=None,
                 submission_timestamp=None, insufficient_task_input_errors=None, expires=None):
        """
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        :param submission_timestamp: time stamp of when this task was submitted
        :type submission_timestamp: datetime.datetime | None
        :param insufficient_task_input_errors: error codes that describe where
            the input was not sufficient to properly analyze the task.
        :type insufficient_task_input_errors: list(int) | None
        :param expires: The earliest time that the results of this task may expire.
        :type expires: datetime.datetime | None
        """
        self.__task_uuid = task_uuid
        self.__submission_timestamp = submission_timestamp
        self.__error = error
        self.__error_exception = error_exception
        self.__score = score
        self.__insufficient_task_input_errors = insufficient_task_input_errors
        self.__expires = expires

    @property
    def task_uuid(self):
        return self.__task_uuid

    @property
    def error(self):
        return self.__error

    @property
    def error_exception(self):
        return self.__error_exception

    @property
    def score(self):
        if self.__score is not None:
            return self.__score
        if self.error:
            return 0
        raise NoResultFoundError("Task not complete")

    @property
    def submission_timestamp(self):
        return self.__submission_timestamp

    @property
    def insufficient_task_input_errors(self):
        return self.__insufficient_task_input_errors

    @property
    def expires(self):
        return self.__expires

    def set_score(self, score):
        """
        Update the score of this task. May only be done if not set yet (see
        `self.is_complete()`).

        :param score: Score to set
        :type score: `int`
        """
        if self.__score is not None:
            raise Error("Double-setting score")
        if 0 <= score <= 100:
            self.__score = int(score)
        else:
            raise Error("Invalid score")

    def is_complete(self):
        """
        Check if this task represents a complete task

        :returns: True if this task is marked completed, False otherwise.
        :rtype: `bool`
        """
        return self.__score is not None or self.__error is not None

    def __eq__(self, other):
        return isinstance(other, SubmittedTask) and other.task_uuid == self.task_uuid

    def __str__(self):
        s = "AnalysisTask"
        if self.task_uuid:
            s += " {}".format(self.task_uuid)
        if self.submission_timestamp:
            s += " {}".format(self.submission_timestamp)
        if self.error_exception:
            s += "(error: {})".format(self.error_exception)
        elif self.error:
            s += "(error: {})".format(self.error)
        elif self.__score is not None:
            s += "(score: {})".format(self.__score)
        return s


class SubmittedFileTask(SubmittedTask):
    """
    Representation of a file task that was submitted
    """
    def __init__(self, file_md5, file_sha1, file_sha256, task_uuid,
                 filename=None, score=None,
                 error=None, error_exception=None, submission_timestamp=None,
                 insufficient_task_input_errors=None, expires=None):
        """
        :param file_md5: The MD5 of the submitted file
        :type file_md5: `str`
        :param file_sha1: The SHA1 of the submitted file
        :type file_sha1: `str`
        :param file_sha256:  The SHA256 of the submitted file
        :type file_sha256: `str`
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param filename: The name of the file that was submitted
        :type filename: `str` | None
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        :param submission_timestamp: time stamp of when this task was submitted
        :type submission_timestamp: datetime.datetime | None
        :param insufficient_task_input_errors: error codes that describe where invalid
            input was provided
        :type insufficient_task_input_errors: list(int) | None
        :param expires: The earliest time that the results of this task may expire.
        :type expires: datetime.datetime | None
        """
        if not file_md5 or len(file_md5) != 32:
            raise ValueError("Invalid file MD5")
        if not file_sha1 or len(file_sha1) != 40:
            raise ValueError("Invalid file SHA1")
        if not file_sha256 or len(file_sha256) != 64:
            raise ValueError("Invalid file SHA256")
        SubmittedTask.__init__(
            self,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception,
            submission_timestamp=submission_timestamp,
            insufficient_task_input_errors=insufficient_task_input_errors,
            expires=expires,
        )
        self.__file_md5 = file_md5
        self.__file_sha1 = file_sha1
        self.__file_sha256 = file_sha256
        self.__filename = filename

    @property
    def file_md5(self):
        return self.__file_md5

    @property
    def file_sha1(self):
        return self.__file_sha1

    @property
    def file_sha256(self):
        return self.__file_sha256

    @property
    def filename(self):
        return self.__filename

    def __str__(self):
        s = "%s: MD5=%s, SHA1=%s" % (
            SubmittedTask.__str__(self),
            self.file_md5,
            self.file_sha1,
        )
        if self.file_sha256:
            s += ", SHA256=%s" % self.file_sha256
        if self.filename:
            s += ", name=%s" % self.filename
        return s


class SubmittedURLTask(SubmittedTask):
    """
    Representation of a URL task that was submitted
    """
    def __init__(self, url, task_uuid, referer=None, score=None, error=None, error_exception=None,
                 submission_timestamp=None, expires=None):
        """
        :param url: The URL that was submitted
        :type url: `str`
        :param task_uuid: The returned task-UUID, if one was returned
        :type task_uuid: `str` | None
        :param referer:  The refer(r)er which was submitted for the URL
        :type referer: `str`
        :param score: The returned score, if one is available
        :type score: `int` | None
        :param error: The returned error, if submission failed
        :type error: `str` | None
        :param error_exception: Detailed exception data, if submission failed
        :type error_exception: `AnalysisAPIError` | None
        :param submission_timestamp: time stamp of when this task was submitted
        :type submission_timestamp: datetime.datetime | None
        :param expires: The earliest time that the results of this task may expire.
        :type expires: datetime.datetime | None
        """
        SubmittedTask.__init__(
            self,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception,
            submission_timestamp=submission_timestamp,
            expires=expires,
        )
        self.__url = url
        self.__referer = referer

    @property
    def url(self):
        return self.__url

    @property
    def referer(self):
        return self.__referer

    def __str__(self):
        s = "%s: URL=%s" % (
            SubmittedTask.__str__(self),
            self.url,
        )
        if self.referer:
            s += ", refer(r)er=%s" % self.referer
        return s


class ExportedReport(object):
    """
    Representation of a report that was exported
    """

    def __init__(
            self,
            task_uuid,
            report_uuid=None,
            report_stream=None,
            export_timestamp=None,
            export_error=None):
        """
        :param str task_uuid: Unique identifier for the task that was exported
        :param str|None report_uuid: Unique identifier for the exported report
        :param stream|None report_stream: Stream containing the downloaded report
        :param datetime.datetime export_timestamp: Time report was exported
        :param str|None export_error: Error that occurred while requesting or performing the export
        """
        self.__task_uuid = task_uuid
        self.__report_uuid = report_uuid
        self.__report_stream = report_stream
        self.__export_timestamp = export_timestamp
        self.__export_error = export_error

    @property
    def task_uuid(self):
        return self.__task_uuid

    @property
    def report_uuid(self):
        return self.__report_uuid

    @property
    def report_stream(self):
        return self.__report_stream

    @property
    def export_timestamp(self):
        return self.__export_timestamp

    @property
    def export_error(self):
        return self.__export_error

    def __eq__(self, other):
        return (isinstance(other, ExportedReport)
                and other.task_uuid == self.task_uuid
                and other.report_uuid == self.report_uuid
                and other.export_error == self.export_error)


class SubmissionHelper(object):
    """
    Helper class for handling submission and task retrieval
    """
    # The max number of task-uuids to print in logging when telling how many tasks
    # are still pending to be completed
    MAX_WAITING_TASK_UUIDS_NUM = 10

    def __init__(self, analysis_client, logger=None, num_retries=10):
        """
        :param analysis_apiclient.AnalysisClientBase analysis_client: The client to use
        :param logging.Logger|None logger: Optional logger to use. If None is provided, log to
            stdout
        :param int num_retries: Number of times to retry network requests on error.
            Use 0 to disable retries or None for endless retries
        """
        self.__analysis_client = analysis_client
        self.__num_retries = num_retries
        if logger:
            self.__logger = logger
        else:
            self.__logger = logging.getLogger('lastline.analysis.api_client')
            self.__logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            self.__logger.addHandler(ch)

    def get_api_utc_timestamp(self):
        """
        Query the API to get its UTC timestamp: do this *before* submitting
        to avoid racing or clock-skew with the local clock

        :returns: Current UTC timestamp according to API
        :rtype: `datetime.datetime`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        return self.__analysis_client.get_api_utc_timestamp()

    def submit_file_stream(self, file_stream, **kwargs):
        """
        Submit a file for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_file_hash` or `submit_file`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_file_stream(<stream>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_file_streams_and_wait_for_completion()` helper
        function.

        NOTE: You may provide any of the parameters
        - file_md5,
        - file_sha1, or
        - file_sha256
        to avoid repeated file-hash calculations. Any hash not provided will be
        generated from the given file-stream.

        :param file_stream: Stream to submit
        :type file_stream: `stream`
        :returns: Submission results
        :rtype: `SubmittedFileTask`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # get the current seek position to put the stream back to exactly
        # this point after reading the file for computing hashes
        file_pos = file_stream.tell()
        try:
            file_md5 = kwargs.pop('file_md5')
            if not file_md5: raise KeyError()
        except KeyError:
            file_md5 = hash_stream(file_stream, 'md5')
            file_stream.seek(file_pos)
        try:
            file_sha1 = kwargs.pop('file_sha1')
            if not file_sha1: raise KeyError()
        except KeyError:
            file_sha1 = hash_stream(file_stream, 'sha1')
            file_stream.seek(file_pos)
        try:
            file_sha256 = kwargs.pop('file_sha256')
            if not file_sha256: raise KeyError()
        except KeyError:
            file_sha256 = hash_stream(file_stream, 'sha256')
            file_stream.seek(file_pos)

        try:
            filename = kwargs.pop('filename')
        except KeyError:
            if hasattr(file_stream, 'name'):
                filename = os.path.basename(file_stream.name)
            else:
                # auto-select in the API
                filename = None

        # submit_file_hash does not take the "delete_after_analysis" parameter
        try:
            delete_after_analysis = kwargs.pop('delete_after_analysis')
        except KeyError:
            delete_after_analysis = False
        # same for "mime_type" (only for submit_file_hash)
        try:
            mime_type = kwargs.pop('mime_type')
        except KeyError:
            mime_type = None
        self.__logger.info("Submitting file %s (md5=%s, sha1=%s, sha256=%s)",
                           filename or '<unnamed>', file_md5, file_sha1,
                           file_sha256)
        result_data = None
        task_uuid = None
        submission_timestamp = None
        score = None
        error = None
        error_exception = None
        submit_by_file = True
        insufficient_task_input_errors = None
        expires = None
        # Only submit file hash if bypass_cache is not enabled
        if not kwargs.get('bypass_cache'):
            try:
                result_data = self.__analysis_client.submit_file_hash(
                    md5=file_md5, sha1=file_sha1, sha256=file_sha256,
                    filename=filename,
                    full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                    mime_type=mime_type,
                    **kwargs
                )['data']
            except AnalysisAPIError as err:
                # NOTE: In theory we should only submit again if the file is not
                # known, but submitting again either way does not hurt
                self.__logger.debug("Submitting file by hash failed: %s", err)
            else:
                # NOTE: If bypass_cache is not enabled and we submitted file hash successfully
                # we will not submit the file again.
                submit_by_file = False
        if submit_by_file:
            try:
                result_data = self.__analysis_client.submit_file(
                    file_stream=file_stream,
                    filename=filename,
                    full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                    delete_after_analysis=delete_after_analysis,
                    **kwargs
                )['data']
            except AnalysisAPIError as err2:
                # we are handling this error, and it's not a bug in the code, so
                # logged just as warning
                self.__logger.warning(
                    "Submitting file %s (md5=%s, sha1=%s, sha256=%s) failed: %s",
                    filename or '<unnamed>', file_md5, file_sha1, file_sha256, err2)

                error = str(err2)
                error_exception = err2

        if result_data is not None:
            try:
                task_uuid = result_data['task_uuid']
            except KeyError:
                # this path is not possible according to the API documentation,
                # but just to be on the save side...
                error = "no task returned"
            submission_timestamp = result_data.get('submission_timestamp')
            score = result_data.get('score')
            insufficient_task_input_errors = result_data.get('insufficient_task_input_errors')
            try:
                expires = parse_datetime(result_data['expires'])
            except KeyError:
                expires = None

        # NOTE: We insert the data we have already now right away. This way the
        # caller can skip waiting for completion if possible
        return SubmittedFileTask(
            file_md5=file_md5,
            file_sha1=file_sha1,
            file_sha256=file_sha256,
            filename=filename,
            task_uuid=task_uuid,
            score=score,
            error=error,
            error_exception=error_exception,
            submission_timestamp=submission_timestamp,
            insufficient_task_input_errors=insufficient_task_input_errors,
            expires=expires,
        )

    def submit_filename(self, filename, **kwargs):
        """
        Submit a file for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_file_hash` or `submit_file`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_filename(<filename>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_filenames_and_wait_for_completion()` helper function.

        :param filename: File on the local filesystem to submit
        :type filename: `str`
        :returns: Submission results
        :rtype: `SubmittedFileTask`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # NOTE: We release this file to customers who may run this code on Windows. Make
        # sure to open the file in binary-mode. Python will otherwise truncate the file
        # at the location where it detects non-text, and does so without any warning
        with open(filename, 'rb') as file_stream:
            return self.submit_file_stream(file_stream, **kwargs)

    def submit_url(self, url, **kwargs):
        """
        Submit a URL for analysis and retrieve results if they are immediately
        available. Additional parameters passed to this function are forwarded
        to the client (see `submit_url`).

        NOTE: To avoid a race-condition between submission and polling for
        results, use the following approach::

            helper = SubmissionHelper(<client>)
            ts = helper.get_api_utc_timestamp()
            submission = helper.submit_url(<url>, referer=<referer>)
            helper.wait_for_completion_of_submission(submission, ts)

        or use the `submit_urls_and_wait_for_completion()` helper function.

        :param url: URL to submit
        :type url: `str`
        :returns: Submission results
        :rtype: `SubmittedURLTask`
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        self.__logger.info("Submitting URL %s", url)
        result_data = None
        task_uuid = None
        submission_timestamp = None
        score = None
        error = None
        error_exception = None
        expires = None
        try:
            result_data = self.__analysis_client.submit_url(
                url=url,
                full_report_score=ANALYSIS_API_NO_REPORT_DETAILS,
                **kwargs
            )['data']
        except AnalysisAPIError as err:
            # we are handling this error, and it's not a bug in the code, so
            # logged just as warning
            self.__logger.warning("Submitting URL %s failed: %s", url, err)
            error = str(err)
            error_exception = err

        if result_data is not None:
            try:
                task_uuid = result_data['task_uuid']
            except KeyError:
                # this path is not possible according to the API documentation,
                # but just to be on the save side...
                error = "no task returned"
            else:
                submission_timestamp = result_data.get('submission_timestamp')
            score = result_data.get('score')
            try:
                expires = parse_datetime(result_data['expires'])
            except KeyError:
                expires = None

        # NOTE: We insert the data we have already now right away. This way the
        # caller can skip waiting for completion if possible
        return SubmittedURLTask(
            url=url,
            referer=kwargs.get('referer'),
            task_uuid=task_uuid,
            submission_timestamp=submission_timestamp,
            score=score,
            error=error,
            error_exception=error_exception,
            expires=expires,
        )

    def submit_file_streams_and_wait_for_completion(
            self, file_streams,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of files and wait for completion: For each file, submit
        the file for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_file_hash` or `submit_file`).

        :param file_streams: List of streams to submit
        :type file_streams: `list`(`stream`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever.
            NOTE: If waiting times out, the result will contain elements whose
            score is set to `None`. This method does *not* raise
            `WaitResultTimeout` to allow retrieving the result even when waiting
            for completion timed out.
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedFileTask`)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        start_ts = self.get_api_utc_timestamp()
        self.__logger.info("Submitting %d files", len(file_streams))
        results = {}
        for file_stream in file_streams:
            # the caller may want to submit all files using the same
            # filename, so we really forward *all* arguments
            results[file_stream] = self.submit_file_stream(
                file_stream=file_stream, **kwargs
            )

        try:
            self.wait_for_completion(
                results,
                start_timestamp=start_ts,
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=kwargs.get('verify', True)
            )
        except WaitResultTimeout as err:
            self.__logger.warning("Waiting for file submissions completion "
                                  "failed: %s", err)
        return results

    def submit_filenames_and_wait_for_completion(
            self, filenames,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of files and wait for completion: For each file, submit
        the file for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_file_hash` or `submit_file`).

        :param filenames: List of files on the local filesystem to submit
        :type filenames: `list`(`str`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever.
            NOTE: If waiting times out, the result will contain elements whose
            score is set to `None`. This method does *not* raise
            `WaitResultTimeout` to allow retrieving the result even when waiting
            for completion timed out.
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedFileTask`)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        file_streams = {}
        try:
            # NOTE: use set() to make sure the list is unique
            for filename in set(filenames):
                # NOTE: We release this file to customers who may run this code on Windows. Make
                # sure to open the file in binary-mode. Python will otherwise truncate the file
                # at the location where it detects non-text, and does so without any warning
                file_streams[open(filename, 'rb')] = filename

            results_streams = self.submit_file_streams_and_wait_for_completion(
                file_streams=list(file_streams.keys()),
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                **kwargs
            )
            # map by-stream results into by-name results
            results = {}
            for file_stream, result in results_streams.items():
                filename = file_streams[file_stream]
                results[filename] = result
            return results
        finally:
            for file_stream in file_streams:
                file_stream.close()

    def submit_urls_and_wait_for_completion(
            self, urls,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            **kwargs):
        """
        Submit a list of URLs and wait for completion: For each URL, submit
        the URL for analysis, wait for completion, and retrieve results.
        Additional parameters passed to this function are forwarded to the
        client (see `submit_url`).

        :param urls: List of URLs to submit
        :type urls: `list`(`str`)
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :returns: Dictionary of results
        :rtype: `dict`(`SubmittedURLTask`)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        start_ts = self.get_api_utc_timestamp()
        self.__logger.info("Submitting %d URLs", len(urls))
        results = {}
        for url in urls:
            self.__logger.info("Submitting URL %s", url)
            results[url] = self.submit_url(url, **kwargs)

        try:
            self.wait_for_completion(
                results,
                start_timestamp=start_ts,
                wait_completion_interval_seconds=
                    wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=kwargs.get('verify', True)
            )
        except WaitResultTimeout as err:
            self.__logger.warning("Waiting for URL submissions completion "
                                  "failed: %s", err)
        return results

    def wait_for_completion_of_submission(
            self, submission, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Wait for completion of a given tasks.

        :param submission: A submitted task. This object is updated in place
            with result data
        :type submission: `SubmittedTask`
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve or use the
            submission_timestamp returned from the submission.
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises WaitResultTimeout: Waiting for results timed out
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        self.wait_for_completion(
            submissions={1:submission},
            start_timestamp=start_timestamp,
            wait_completion_interval_seconds=wait_completion_interval_seconds,
            wait_completion_max_seconds=wait_completion_max_seconds,
            verify=verify,
        )

    def wait_for_completion(
            self, submissions, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Wait for completion of a given dictionary of tasks.

        NOTE: Results are filled in in provided `submissions` dictionary.

        :param submissions: Dictionary of submissions: submission identifier to
            `SubmittedTask` mapping. NOTE: The submission identifier can be an
            arbitrary value unique to the dictionary
        :type submissions: `dict`(id:`SubmittedTask`)
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve or use the
            submission_timestamp returned from the submission.
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :raises WaitResultTimeout: Waiting for results timed out
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        g = self.yield_completed_tasks(
                submissions, start_timestamp,
                wait_completion_interval_seconds=wait_completion_interval_seconds,
                wait_completion_max_seconds=wait_completion_max_seconds,
                verify=verify)
        # wait for completion all the tasks by invoking generator
        for _ in g:
            pass

    def __handle_communication_error(self, e, num_retries):
        """
        Handle CommunicationError exception with retries

        :param CommunicationError e: exception to handle
        :param int|None num_retries: current number of retried
        :return: Number of remaining retries
        :rtype: int
        :raises CommunicationError: If num retries expired.
        """
        if num_retries is None:
            self.__logger.warning(
                "Communication Error - retry sending request. UNLIMITED times left."
            )
        elif num_retries > 0:
            num_retries -= 1
            self.__logger.warning(
                "Communication Error - retry sending request. %d times left.", num_retries
            )
        else:
            self.__logger.warning("Communication error: %s", e)
            raise e
        return num_retries

    def yield_completed_tasks(
            self, submissions, start_timestamp,
            wait_completion_interval_seconds=15,
            wait_completion_max_seconds=None,
            verify=True):
        """
        Returns a generator, which gives completed tasks as soon as they are
        ready.

        NOTE: Results are filled in in provided `submissions` dictionary.

        NOTE: Any `SubmittedTask` instances that are part of the `submissions`
        parameter and that are marked as completed already upon function
        invocation will not be yielded.

        :param submissions: Dictionary of submissions: submission identifier to
            `SubmittedTask` mapping. NOTE: The submission identifier can be an
            arbitrary value unique to the dictionary
        :type submissions: `dict`(id:`SubmittedTask`)
        :param start_timestamp: UTC timestamp before the first submission has
            happened. Use `self.get_api_utc_timestamp()` to retrieve or use the
            submission_timestamp returned from the submission.
        :type start_timestamp: `datetime.datetime`
        :param wait_completion_interval_seconds: How long to wait between polls
            for completion
        :type wait_completion_interval_seconds: `float`
        :param wait_completion_max_seconds: Don't wait for longer than this many
            seconds for completion. If None is specified, wait forever
        :type wait_completion_max_seconds: `float`
        :param verify: if False, disable SSL-certificate verification
        :type verify: `bool`
        :returns: generator that yields completed SubmittedTask objects
        :rtype: `Iterator`(`SubmittedTask`)
        :raises WaitResultTimeout: Waiting for results timed out
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        # find which submissions we're still waiting for and build an index for
        # looking up existing data quickly
        missing_results = {
            result.task_uuid: submission_id
            for submission_id, result in submissions.items()
            if result.task_uuid is not None and not result.is_complete()
        }
        if not missing_results:
            self.__logger.info("No need to wait for completion for any of %d "
                               "submissions", len(submissions))
            return
        self.__logger.info(
            "Waiting for completion of %d/%d submissions",
            len(missing_results),
            len(submissions),
        )

        start_completion_time = time.time()
        end_completion_time = (
            start_completion_time + wait_completion_max_seconds
            if wait_completion_max_seconds is not None else None
        )
        # Number of times to re-sending request
        num_retries = self.__num_retries
        while missing_results:
            waiting_task_uuids = list(missing_results.keys())[
                :SubmissionHelper.MAX_WAITING_TASK_UUIDS_NUM
            ]
            if len(missing_results) > SubmissionHelper.MAX_WAITING_TASK_UUIDS_NUM:
                waiting_tasks = '{},...'.format(','.join(waiting_task_uuids))
            else:
                waiting_tasks = ','.join(waiting_task_uuids)
            self.__logger.debug(
                "Waiting for completion of %d submissions: %s",
                len(missing_results),
                waiting_tasks
            )
            try:
                completed_data = self.__analysis_client.get_completed(
                    after=start_timestamp,
                    verify=verify,
                    include_score=True
                )['data']
            # only ignore the communication error and resending the request
            except CommunicationError as e:
                num_retries = self.__handle_communication_error(e, num_retries)
            else:
                # reset times of retry to the default value if is not None
                if self.__num_retries is not None:
                    num_retries = self.__num_retries
                # resume from here next iteration:
                start_timestamp = completed_data['before']
                if completed_data['tasks']:
                    for task_uuid, score in completed_data['tasks'].items():
                        try:
                            submission_id = missing_results[task_uuid]
                        except KeyError:
                            # someone else is submitting with the same license or
                            # we already had the result
                            continue

                        self.__logger.debug("Got result for task %s", task_uuid)
                        # fill in the details
                        #
                        # NOTE: We're currently NOT checking if the analysis failed.
                        # this will be merged with "score=0" - it's up to the caller
                        # to check (or a future extension)
                        result = submissions[submission_id]
                        result.set_score(score) # result.is_complete() becomes True
                        del missing_results[task_uuid]
                        self.__logger.debug("Got result for task %s: %s",
                                            task_uuid, result)
                        yield result
                if not missing_results:
                    break
                if completed_data['more_results_available']:
                    # If we have more results available to be fetched, don't need to sleep
                    continue

            sleep_timeout = wait_completion_interval_seconds
            if end_completion_time is not None:
                now = time.time()
                if now >= end_completion_time:
                    self.__logger.warning("Waiting for completion of %d "
                                          "submissions timed out",
                                          len(missing_results))
                    raise WaitResultTimeout()
                # make sure we only sleep as long as we have time left before
                # the timeout
                if now + sleep_timeout > end_completion_time:
                    sleep_timeout = end_completion_time - now
            time.sleep(sleep_timeout)

        self.__logger.info("Done waiting for completion of %d submissions",
                           len(submissions))

    def export_and_yield_reports(self, task_uuids, sleep_interval_seconds=15, **kwargs):
        """
        For each task UUID, export an analysis report for the task and yield that report when
        it's ready. Additional parameters passed to this function are forwarded to the
        client (see `export_report`).

        :param list(str) task_uuids: List of task UUIDs to submit
        :param int sleep_interval_seconds: Interval to wait between queries to malscape
        :returns: generator that yields generated reports
        :rtype: Iterator(ExportedReport)
        :raises AnalysisAPIError: Analysis API returns HTTP error or error code (and 'raw' not set)
        :raises CommunicationError: Error contacting Lastline Analyst API.
        """
        self.__logger.info("Exporting %d reports", len(task_uuids))
        report_uuids = []

        resume_after_report_uuid = None
        resume_after_report_uuid_initialized = False
        for task_uuid in task_uuids:
            self.__logger.info("Exporting report for task %s", task_uuid)
            error = None
            exported_report_uuid = None
            try:
                result_data = self.__analysis_client.export_report(
                    uuid=task_uuid,
                    **kwargs
                )['data']
            except AnalysisAPIError as err:
                # we are handling this error, and it's not a bug in the code, so
                # logged just as warning
                self.__logger.warning("Exporting report for task %s failed: %s", task_uuid, err)
                error = str(err)
            else:
                try:
                    exported_report_uuid = result_data['exported_report_uuid']
                except KeyError:
                    # this path is not possible according to the API documentation,
                    # but just to be on the safe side...
                    error = "no report identifier returned"
                else:
                    if not resume_after_report_uuid_initialized:
                        resume_after_report_uuid = result_data.get('resume_after_report_uuid')
                        resume_after_report_uuid_initialized = True

            if exported_report_uuid:
                report_uuids.append(exported_report_uuid)
            else:
                # Task could not be exported, create an error report now
                yield ExportedReport(task_uuid, export_error=error)

        # Now that the exports are initiated, yield them as they complete
        for exported_report in self.yield_exported_reports(
            report_uuids,
            resume_after_report_uuid,
            sleep_interval_seconds=sleep_interval_seconds
        ):
            yield exported_report

    def yield_exported_reports(
        self,
        submitted_report_uuids,
        resume_after_report_uuid,
        sleep_interval_seconds=15
    ):
        """
        Yield exported reports as they become available for download.

        :param list(str) submitted_report_uuids: List of exported report UUIDs we wish to get.
        :param str|None resume_after_report_uuid: The last consumed report UUID. To enumerate
            reports ready for download, specify the last UUID that the client processed; will
            only consider UUIDs of new reports that were made available after the given one. If
            not provided, will query for *all* reports stored to find the submitted_report_uuids.
        :param int sleep_interval_seconds: Interval to wait between queries to malscape
        :returns: generator that yields generated reports
        :rtype: Iterator(ExportedReport)
        """
        if not submitted_report_uuids:
            self.__logger.debug('no need to wait for completion, no reports requested')
            return
        num_retries = self.__num_retries
        self.__logger.info(
            "Waiting for completion of %d exported reports", len(submitted_report_uuids),
        )
        while submitted_report_uuids:
            try:
                reports = self.__analysis_client.get_completed_exported_reports(
                    resume_after_report_uuid
                )['data']['available_reports']
            except CommunicationError as e:
                num_retries = self.__handle_communication_error(e, num_retries)
            else:
                for report in reports:
                    report_uuid = report['exported_report_uuid']
                    if report_uuid in submitted_report_uuids:
                        exported_report = None
                        task_uuid = report['task_uuid']
                        export_timestamp = parse_datetime(report['export_timestamp'])
                        export_error = report.get('export_error')
                        if export_error is not None:
                            # The report could not be exported, so don't even try to fetch it
                            self.__logger.debug(
                                'report %s not available, export failed: %s', report_uuid,
                                export_error
                            )
                            exported_report = ExportedReport(
                                task_uuid,
                                report_uuid=report_uuid,
                                export_timestamp=export_timestamp,
                                export_error=export_error,
                            )
                        else:
                            try:
                                stream = self.__analysis_client.get_exported_report(report_uuid)
                            except CommunicationError as e:
                                num_retries = self.__handle_communication_error(e, num_retries)
                            else:
                                self.__logger.debug('got report %s.', report_uuid)
                                exported_report = ExportedReport(
                                    task_uuid,
                                    report_uuid=report_uuid,
                                    report_stream=stream,
                                    export_timestamp=export_timestamp,
                                )
                        if exported_report:
                            yield exported_report
                            submitted_report_uuids.remove(report_uuid)
                            num_retries = self.__num_retries
                            resume_after_report_uuid = report_uuid
                    else:
                        self.__logger.debug(
                            'not yielding report %s, not in submission list', report_uuid
                        )
            if submitted_report_uuids:
                self.__logger.info(
                    "Sleeping %ds for completion of %d exported reports (%s ...)",
                    sleep_interval_seconds, len(submitted_report_uuids), submitted_report_uuids[0]
                )
                time.sleep(sleep_interval_seconds)


class QueryHelper(object):
    """
    Helper class for handling queries
    """
    def __init__(self, analysis_client, logger=None):
        """
        :param analysis_client: The client to use
        :type analysis_client: `AnalysisClientBase`
        :param logger: Optional logger to use. If None is provided, log to
            stdout
        :type logger: logging.Logger
        """
        self.__analysis_client = analysis_client
        if logger:
            self.__logger = logger
        else:
            self.__logger = logging.getLogger('lastline.analysis.api_client')
            self.__logger.setLevel(logging.DEBUG)
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            self.__logger.addHandler(ch)

    def download_analysis_subject_file(self, task_uuid, password_protected=None):
        """
        Helper method for checking if a file analysis subject is available for
        download

        :param str task_uuid: The task's UUID
        :param str password_protected: If provided, use this password to create a zip which will
            contain the artifact being fetched. The password provided should be using only
            ASCII characters and have max length of 128 characters
        :returns: A file-stream if the file is available, otherwise None
        :rtype: `NamedStringIO`
        """
        results = self.__analysis_client.get_result(
            uuid=task_uuid,
            full_report_score=ANALYSIS_API_NO_REPORT_DETAILS)
        try:
            reports = results['data']['reports']
        except KeyError:
            reports = None
        if not reports:
            return None

        for report in reports:
            report_uuid = report.get('report_uuid')
            if report_uuid:
                try:
                    stream = self.__analysis_client.get_result_artifact(
                        uuid=task_uuid,
                        report_uuid=report_uuid,
                        artifact_name='analysis_subject',
                        password_protected=password_protected,
                    )
                except Error:
                    stream = None
                if stream:
                    return stream
        return None

    def download_analysis_subject_by_file_hash(
        self, md5=None, sha1=None, sha256=None, password_protected=None
    ):
        """
        Helper method for checking if a file is available for download

        :param str md5: Optional md5 hash of the file. Exactly one of the file-hash
            parameters must to be provided
        :param str sha1: Optional sha1 hash of the file. Exactly one of the file-
            hash parameters must to be provided
        :param str sha256: Optional sha256 hash of the file. Exactly one of the
            file-hash parameters must to be provided
        :param str password_protected: If provided, use this password to create a zip which will
            contain the artifact being fetched. The password provided should be using only
            ASCII characters and have max length of 128 characters
        :returns: A file-stream if the file is available, otherwise None
        :rtype: `NamedStringIO`
        """
        result = self.__analysis_client.query_file_hash(
            md5=md5,
            sha1=sha1,
            sha256=sha256)
        if not result['data']['files_found']:
            return None
        return self.download_analysis_subject_file(
            task_uuid=result['data']['tasks'][0]['task_uuid'],
            password_protected=password_protected,
        )


class AnalyzeHelper(object):
    """
    This class provides helper functions used for submitting files and urls to the
    Lastline Analyst API.
    """

    DEFAULT_ANALYST_API_URL = 'https://analysis.lastline.com/analysis'

    @classmethod
    def factory(cls, url, token, key, logger, secure=False):
        """
        Factory for this class
        """

        client = AnalysisClient(
            url,
            key=key,
            api_token=token,
            # the API client is very verbose (in INFO mode) by default
            logger=logger,
            verify_ssl=secure
        )

        return AnalyzeHelper(
            url=url,
            token=token,
            key=key,
            client=client,
            logger=logger
        )

    @staticmethod
    def from_config(conf_file, conf_section, logger, secure):
        """
        Parse the conf file and return a dict with the expected parameters. If the parameter is not
        found in the section, read it with None

        :param str conf_file: The path to the conf file we want to read
        :param str conf_section: The section name used to read the parameters
        :param logging.Logger logger: Logger to use
        :raises: IOError if file doesnt exist
        :raises: ConfigParser.Error if field not present
        """
        conf = configparser.ConfigParser()
        conf.readfp(open(conf_file))

        try:
            url  = conf.get(conf_section, "url")
        except configparser.Error:
            url = None

        if not url:
            url = AnalyzeHelper.DEFAULT_ANALYST_API_URL

        try:
            key  = conf.get(conf_section, "key")
            token  = conf.get(conf_section, "api_token")
        except configparser.Error:
            raise configparser.Error("Missing credentials in configuration")

        return AnalyzeHelper.factory(
            url=url,
            token=token,
            key=key,
            logger=logger,
            secure=secure
        )


    def __init__(self, url, token, key, client, logger):
        """
        Create an instance of AnalyzeHelper

        :param str url: the base url used for the api
        :param str token: The token used for the api
        :param str key: the key used for the api
        :param AnalysisClient client: the client instance
        :param logging.Logger logger: Logger to use
        """

        self._url = url
        self._key = key
        self._token = token
        self._logger = logger
        self._client = client

    def get_client(self):
        """
        Retrieve the client object

        :return: An instance of AnalysisClient configured for an api request
        :rtype: AnalysisClient
        """

        return self._client

    def verify_connectivity(self):
        """
        Check if the given client can talk to the given API and log human-readable reasons if it
        fails

        :return: True if connecitivty works, False otherwise
        :rtype: bool
        """
        self._logger.info("Testing connectivity to Lastline analysis API server")
        ping_successful = False
        try:
            # NOTE: We check using `ping()` first, because it checks basic connectivity and
            # credentials. Later, we also check using `get_completed()`, because it's one of the
            # functions that we invoke that require more privileges than just connecting to the API
            # for pushing submissions.
            # If a client is using credentials that don't allow fetching results, we need to alert
            # the user.
            self._client.ping()
            ping_successful = True
            self._client.completed(after=datetime.datetime.now())
        except requests.ConnectionError as err:
            self._logger.error(
                "Failed to connect to API server at %s, please make sure the API server is "
                "reachable: %s", self._url, err
            )
            return False
        except ssl.SSLError as err:
            self._logger.error(
                "Failed to verify SSL certificate for API at %s: %s",
                self._url, err)
            return False
        except AnalysisAPIError as err:
            if err.error_code == ANALYSIS_API_INVALID_CREDENTIALS:
                self._logger.error(
                    "Invalid credentials for %s: failed to authenticate to API server", self._url
                )
            elif ping_successful:
                # if we're partly successful, give the user a bit more information what could be the
                # problem
                self._logger.error(
                    "API Credentials used for %s don't allow required functionality:"
                    "%s", self._url, err
                )
            else:
                self._logger.error("Failed to communicate with API at %s: %s", self._url, err)
            return False
        except Exception as err:
            self._logger.error("Error in HTTP request to analysis API server: %s", err)
            return False
        else:
            self._logger.info("Successfully connected to Lastline analysis API server")
            return True

    def _write_result(self, result, result_filename):
        """
        Open the filename and write the result

        :param str result: The results to write to the file
        :param str result_filename: The location of the file to write the result to
        :return: True if write operation was successful, False otherwise
        :rtype: bool
        """

        try:
            with open(result_filename, "w") as f:
                f.write(result)
        except IOError as err:
            self._logger.error("Failed to write result to file %s: %s", result_filename, err)
            return False
        return True

    def store_result(self, task_uuid, base_result_filename):
        """
        Retrieve analysis results and format/store them as JSON and XML

        :param str task_uuid: The task to fetch results for
        :param str base_result_filename: Name under which to store the result files as
            (with .json/.xml suffixes)
        :return: True if storing was successful, False otherwise
        :rtype: bool
        """

        report_url = os.path.join(self._url, 'portal#/analyst/task', task_uuid)
        try:
            json_result = self._client.get_result(task_uuid, raw=True)
            json_analysis_tags = self._client.get_analysis_tags(task_uuid, raw=True)
        except CommunicationError as err:
            self._logger.error("Failed to connect to API server: %s", err)
            return False
        except AnalysisAPIError as err:
            self._logger.error("Error in HTTP request to API: %s", err)
            return False

        try:
            result = simplejson.loads(json_result)
            analysis_tags = simplejson.loads(json_analysis_tags)
            json_report_url = simplejson.dumps({'report_url': report_url})
        except Exception as err:
            logging.error("Unexpected response format for UUID %s: %s", task_uuid, err)
            return False

        if not result['success'] or not analysis_tags['success']:
            self._logger.error("Error fetching results for UUID %s: %s", task_uuid, result)
            return False
        json_result_filename = base_result_filename + '_result.json'
        json_report_result_filename = base_result_filename + '_report_url.json'
        json_analysis_tags_filename = base_result_filename + '_analysis_tags.json'
        self._write_result(json_result, json_result_filename)
        self._write_result(json_analysis_tags, json_analysis_tags_filename)
        self._write_result(json_report_url, json_report_result_filename)

        # first one (in json) was successful.
        # Now let's get it in raw XML.
        try:
            xml_result = self._client.get_result(task_uuid, requested_format="xml")
            analysis_tags_xml = self._client.get_analysis_tags(task_uuid, requested_format="xml")
        except CommunicationError as err:
            self._logger.error("Failed to connect to API server: %s", err)
            return False
        except AnalysisAPIError as err:
            self._logger.error("Error in HTTP request to API: %s", err)
            return False

        xml_result_filename = base_result_filename + '_result.xml'
        xml_analysis_tags_filename = base_result_filename + '_analysis_tags.xml'
        self._write_result(xml_result, xml_result_filename)
        self._write_result(analysis_tags_xml, xml_analysis_tags_filename)

        return True


#############################################################################
#
# END API-CLIENT FUNCTIONALITY
#
# START API-SHELL FUNCTIONALITY
#
# NOTE: We only keep this code in this module for backwards-compatibility
import sys
import optparse


def init_shell(banner):
    """Set up the iPython shell."""
    # NOTE: We use a local import here to avoid requiring IPython when just using the
    # module without the shell
    try:
        # pylint: disable=E0611,F0401
        from IPython.frontend.terminal import embed
        shell = embed.InteractiveShellEmbed(banner1=banner)
    except ImportError: # iPython < 0.11
        import IPython
        # pylint: disable=E1101
        # pylint won't find the class if a newer version is installed
        shell = IPython.Shell.IPShellEmbed()
        shell.set_banner(banner)
    return shell


def main(argv):
    deprecation_notice = "** DEPRECATION NOTICE: USE analysis_apiclient_shell.py INSTEAD **"
    parser = optparse.OptionParser(usage="""
{deprecation_notice}

Run client for analysis api with the provided credentials

    %prog access_key api_token

{deprecation_notice}
""".format(deprecation_notice=deprecation_notice))
    parser.add_option("-u", "--api-url", dest="api_url",
        type="string", default="https://analysis.lastline.com",
        help="send API requests to this URL (debugging purposes)")

    (cmdline_options, args) = parser.parse_args(argv[1:])
    if len(args) != 2:
        parser.print_help()
        return 1

    namespace = {}
    namespace["analysis"] = AnalysisClient(cmdline_options.api_url,
                                           key=args[0],
                                           api_token=args[1])

    shell = init_shell(banner=deprecation_notice)
    shell(local_ns=namespace, global_ns=namespace)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
