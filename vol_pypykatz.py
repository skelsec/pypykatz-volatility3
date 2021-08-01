#
# Author:
#  Tamas Jos (@skelsec)
#
#


import logging
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

from pypykatz.pypykatz import pypykatz as pparser

vollog = logging.getLogger(__name__)


class pypykatz(interfaces.plugins.PluginInterface):

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols", description="Windows kernel symbols"
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]

    def run(self):
        return renderers.TreeGrid(
            [
                ("Credential Type", str),
                ("Domain Name", str),
                ("Username", str),
                ("NThash", str),
                ("LMHash", str),
                ("SHAHash", str),
                ("masterkey", str),
                ("masterkey (sha1)", str),
                ("key_guid", str),
                ("password", str),
            ],
            pparser.go_volatility3(self),
        )
