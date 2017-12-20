# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class MediaUrl(Model):
    """MediaUrl data.

    :param url: Url for the media.
    :type url: str
    :param profile: Optional profile hint to the client to differentiate
     multiple MediaUrl objects from each other.
    :type profile: str
    """

    _attribute_map = {
        'url': {'key': 'url', 'type': 'str'},
        'profile': {'key': 'profile', 'type': 'str'},
    }

    def __init__(self, url=None, profile=None):
        super(MediaUrl, self).__init__()
        self.url = url
        self.profile = profile
