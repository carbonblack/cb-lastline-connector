from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider,
                                                    AnalysisPermanentError,
                                                    AnalysisTemporaryError,
                                                    AnalysisResult)
import cbint.utils.feed
import logging
from analysis_apiclient import AnalysisClient, AnalysisAPIError, FileNotAvailableError
from time import sleep
import re

log = logging.getLogger(__name__)


class LastlineProvider(BinaryAnalysisProvider):
    def __init__(self, name, lastline_url, lastline_api_key, lastline_api_token, verify_ssl=False):
        super(LastlineProvider, self).__init__(name)
        self.lastline_analysis = AnalysisClient(lastline_url, lastline_api_key, lastline_api_token,
                                                verify_ssl=verify_ssl)
        self.feed_link_prefix = "%s/portal#/analyst/task/" % lastline_url
        if self.feed_link_prefix.lower().find("analysis.lastline.com") >= 0:
            self.feed_link_prefix = "https://user.lastline.com/portal#/analyst/task/"

    def get_uuid(self, response):
        try:
            task_uuid = response.get('data', {}).get('task_uuid', None)
        except AttributeError:
            raise AnalysisTemporaryError(message="Invalid response from LastLine: %s" % response, retry_in=120)
        else:
            if not task_uuid:
                raise AnalysisTemporaryError(message="No UUID for result: %s" % response, retry_in=120)

        return task_uuid

    def make_result(self, task_uuid):
        try:
            result = self.lastline_analysis.get_result(task_uuid)
            result = result.get('data', {})
        except Exception as e:
            raise AnalysisTemporaryError(message="API error: %s" % str(e), retry_in=120)
        else:
            if 'error' in result:
                raise AnalysisTemporaryError(message=result['error'], retry_in=120)
            score = int(result.get('score', 0))
            if score == 0:
                malware_result = "Benign"
            else:
                reasons = "; ".join(result.get('malicious_activity', []))
                malware_result = "Potential malware: %s" % reasons

            return AnalysisResult(message=malware_result, extended_message="",
                                  link=re.sub("(?<!:)/{2,}", "/", "%s/%s" % (self.feed_link_prefix, task_uuid)),
                                  score=score)

    def check_result_for(self, md5sum):
        try:
            response = self.lastline_analysis.submit_file_hash(md5=md5sum)
        except FileNotAvailableError as e:
            log.info("check_result_for: FileNotAvailable")
            # the file does not exist yet.
            return None
        except AnalysisAPIError as e:
            raise AnalysisTemporaryError(message="API error: %s" % str(e), retry_in=120)
        else:
            task_uuid = self.get_uuid(response)
            return self.make_result(task_uuid)

    def analyze_binary(self, md5sum, binary_file_stream):
        log.info("Submitting binary %s to LastLine" % md5sum)

        try:
            response = self.lastline_analysis.submit_file(binary_file_stream)
        except AnalysisAPIError as e:
            raise AnalysisTemporaryError(message="API error: %s" % str(e), retry_in=120)

        task_uuid = self.get_uuid(response)

        retries = 10
        while retries:
            sleep(10)
            result = self.lastline_analysis.get_progress(task_uuid)
            if result.get('data', {}).get('completed', 0) == 1:
                return self.make_result(task_uuid)
            retries -= 1

        raise AnalysisTemporaryError(message="Maximum retries (10) exceeded submitting to LastLine", retry_in=120)


class LastlineConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('(os_type:windows OR os_type:osx) orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def integration_name(self):
        return 'Cb LastLine Connector 1.2.12'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("lastline_quick_scan_threads", 1)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("lastline_deep_scan_threads", 3)

    def get_provider(self):
        lastline_provider = LastlineProvider(self.name, self.lastline_url, self.lastline_api_key,
                                             self.lastline_api_token, verify_ssl=self.lastline_verify_ssl)
        return lastline_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="Lastline Detonation Analysis",
                                              tech_data="An on-premise LastLine device or LastLine cloud service account is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with Lastline.",
                                              provider_url="http://www.lastline.com/",
                                              icon_path='/usr/share/cb/integrations/lastline/lastline-logo.png',
                                              display_name="Lastline", category="Connectors")

    def validate_config(self):
        super(LastlineConnector, self).validate_config()

        self.check_required_options(["lastline_url", "lastline_api_key", "lastline_api_token"])
        self.lastline_url = self.get_config_string("lastline_url", None)
        self.lastline_api_key = self.get_config_string("lastline_api_key", None)
        self.lastline_api_token = self.get_config_string("lastline_api_token", None)
        self.lastline_verify_ssl = self.get_config_boolean("lastline_server_sslverify", False)

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/lastline"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = LastlineConnector('lastlinetest', configfile=config_path, work_directory=temp_directory,
                               logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()
