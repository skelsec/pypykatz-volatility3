#
# Author:
#  Tamas Jos (@skelsec)
#
#


import logging
from typing import List

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

from pypykatz.pypykatz import pypykatz as pparser

vollog = logging.getLogger(__name__)

framework_version = constants.VERSION_MAJOR

class pypykatz(interfaces.plugins.PluginInterface):
    _required_framework_version = (framework_version, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        reqs = []
        if framework_version == 1:
            kernel_layer_name = 'primary'
            reqs = [requirements.TranslationLayerRequirement(name = kernel_layer_name,
                                                                    description = 'Memory layer for the kernel',
                                                                    architectures = ["Intel32", "Intel64"]),
                        requirements.SymbolTableRequirement(name = "nt_symbols",
                                                            description = "Windows kernel symbols"),
                        requirements.PluginRequirement(
                            name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
                        ),
                    ]
        elif framework_version == 2:
            kernel_layer_name = 'kernel'
            reqs = [requirements.ModuleRequirement(name = kernel_layer_name,
                                                        description = 'Windows kernel',
                                                        architectures = ["Intel32", "Intel64"]),
                    requirements.PluginRequirement(
                        name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
                    ),
                    ]
        else:
            # The highest major version we currently support is 2.
            raise RuntimeError(f"Framework interface version {framework_version} is  currently not supported.")

        return reqs

    def run(self):
        return pparser.go_volatility3(self, framework_version)
