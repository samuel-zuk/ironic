# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
# Copyright (c) 2019-2021 Dell Inc. or its subsidiaries.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Test class for DRAC boot interface
"""

from unittest import mock

from oslo_utils import importutils

from ironic.common import boot_devices
from ironic.conductor import task_manager
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.drivers.modules.drac import utils as test_utils
from ironic.tests.unit.objects import utils as obj_utils

sushy = importutils.try_import('sushy')

INFO_DICT = dict(db_utils.get_test_redfish_info(), **test_utils.INFO_DICT)


@mock.patch.object(redfish_utils, 'get_system', autospec=True)
class DracBootTestCase(test_utils.BaseDracTest):

    def setUp(self):
        super(DracBootTestCase, self).setUp()
        self.node = obj_utils.create_test_node(
            self.context, driver='idrac', driver_info=INFO_DICT)

    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       autospec=True)
    def test_validate_correct_vendor(self, mock_get_system,
                                     mock_validate_image_properties):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.instance_info.update(
                {'kernel': 'kernel',
                 'ramdisk': 'ramdisk',
                 'image_source': 'http://image/source'}
            )

            task.node.driver_info.update(
                {'deploy_kernel': 'kernel',
                 'deploy_ramdisk': 'ramdisk',
                 'bootloader': 'bootloader'}
            )

            task.node.properties['vendor'] = "Dell Inc."

            task.driver.boot.validate(task)

    def test__set_boot_device_persistent(self, mock_get_system):
        mock_manager = mock.MagicMock()
        mock_system = mock_get_system.return_value
        mock_system.managers = [mock_manager]
        mock_manager_oem = mock_manager.get_oem_extension.return_value

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot._set_boot_device(
                task, boot_devices.CDROM, persistent=True)

            mock_manager_oem.set_virtual_boot_device.assert_called_once_with(
                sushy.VIRTUAL_MEDIA_CD, persistent=True, system=mock_system)

    def test__set_boot_device_cd(self, mock_get_system):
        mock_system = mock_get_system.return_value
        mock_manager = mock.MagicMock()
        mock_system.managers = [mock_manager]
        mock_manager_oem = mock_manager.get_oem_extension.return_value

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot._set_boot_device(task, boot_devices.CDROM)

            mock_manager_oem.set_virtual_boot_device.assert_called_once_with(
                sushy.VIRTUAL_MEDIA_CD, persistent=False, system=mock_system)

    def test__set_boot_device_floppy(self, mock_get_system):
        mock_system = mock_get_system.return_value
        mock_manager = mock.MagicMock()
        mock_system.managers = [mock_manager]
        mock_manager_oem = mock_manager.get_oem_extension.return_value

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot._set_boot_device(task, boot_devices.FLOPPY)

            mock_manager_oem.set_virtual_boot_device.assert_called_once_with(
                sushy.VIRTUAL_MEDIA_FLOPPY, persistent=False,
                system=mock_system)

    def test__set_boot_device_disk(self, mock_get_system):
        mock_system = mock_get_system.return_value

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot._set_boot_device(task, boot_devices.DISK)

            self.assertFalse(mock_system.called)
