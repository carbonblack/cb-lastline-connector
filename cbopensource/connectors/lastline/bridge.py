from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import time
import logging
import os


log = logging.getLogger(__name__)


class LastlineProvider(BinaryAnalysisProvider):
    def __init__(self, name):
        super(LastlineProvider, self).__init__(name)

    def check_result_for(self, md5sum):
        # TODO: finish
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        # TODO: finish
        pass


class LastlineConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        # TODO: finish

        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('(os_type:windows OR os_type:osx) orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        return 4

    def get_provider(self):
        lastline_provider = LastlineProvider(self.name)
        return lastline_provider

    def get_metadata(self):
        # TODO: finish
        return cbint.utils.feed.generate_feed(self.name, summary="SUMMARY PLACEHOLDER",
                        tech_data="TECH DATA PLACEHOLDER",
                        provider_url="PROVIDER URL",
                        icon_path='/usr/share/cb/integrations/lastline/lastline-logo.png',
                        display_name="Lastline", category="Connectors")

    def validate_config(self):
        super(LastlineConnector, self).validate_config()

        # TODO: finish

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/lastline"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = LastlineConnector('lastlinetest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()