# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import unittest

from cloudify import exceptions as cfy_exc
from cloudify import mocks as cfy_mocks
from storage_plugin import volume
import vcloud_plugin_common
from tests.unittests import test_mock_base
import network_plugin


class StoaragePluginVolumeMockTestCase(test_mock_base.TestBase):

    # vapp name used for tests
    VAPPNAME = "some_other"

    def test_creation_validation_external_resource(self):
        fake_client = self.generate_client()
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        # use external without resorse_id
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        fake_client.get_disks.assert_called_with('vdc_name')
        # with resource id, but without disks(no disks for this client)
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'resource_id': 'some',
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        # good case for external resource
        fake_client.get_disks = mock.MagicMock(return_value=[
            [
                self.generate_fake_client_disk('some'),
                self.generate_fake_vms_disk('some')
            ]
        ])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.creation_validation(ctx=fake_ctx)

    def test_creation_validation_internal(self):
        fake_client = self.generate_client()
        # internal resource without volume
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        fake_client.get_disks.assert_called_with('vdc_name')
        # internal resourse wit volume and name,
        # but already exist such volume
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'volume': {
                    'name': 'some'
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_client.get_disks = mock.MagicMock(return_value=[
            [
                self.generate_fake_client_disk('some'),
                self.generate_fake_vms_disk('some')
            ]
        ])
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        # correct name but without size
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'volume': {
                    'name': 'some-other'
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.creation_validation(ctx=fake_ctx)
        # good case
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'volume': {
                    'name': 'some-other',
                    'size': 11
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.creation_validation(ctx=fake_ctx)

    def test_delete_volume(self):
        fake_client = self.generate_client()
        # external resource
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.delete_volume(ctx=fake_ctx)
        # cant't add disk
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'volume': {
                    'name': 'some-other',
                    'size': 11
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.delete_volume(ctx=fake_ctx)
        fake_client.delete_disk.assert_called_with(
            'vdc_name', 'some-other'
        )
        # positive case
        fake_client.delete_disk = mock.MagicMock(
            return_value=(
                True, self.generate_task(
                    vcloud_plugin_common.TASK_STATUS_SUCCESS
                )
            )
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.delete_volume(ctx=fake_ctx)

    def test_create_volume(self):
        fake_client = self.generate_client()
        # external resource
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': True,
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.create_volume(ctx=fake_ctx)
        # fail on create volume
        fake_ctx = cfy_mocks.MockCloudifyContext(
            node_id='test',
            node_name='test',
            properties={
                'use_external_resource': False,
                'volume': {
                    'name': 'some-other',
                    'size': 11
                },
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                volume.create_volume(ctx=fake_ctx)
        fake_client.add_disk.assert_called_with(
            'vdc_name', 'some-other', 11534336
        )
        # positive case
        disk = mock.Mock()
        disk.get_Tasks = mock.MagicMock(
            return_value=[self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )]
        )
        fake_client.add_disk = mock.MagicMock(
            return_value=(True, disk)
        )
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.create_volume(ctx=fake_ctx)

    def test_volume_operation(self):
        fake_ctx, fake_client = self._gen_volume_context_and_client()

        def _run_volume_operation(fake_ctx, fake_client, operation):
            with mock.patch(
                'vcloud_plugin_common.ctx', fake_ctx
            ):
                with mock.patch(
                    'storage_plugin.volume.ctx', fake_ctx
                ):
                    volume._volume_operation(fake_client, operation)
        # use external resource, no disks
        _run_volume_operation(fake_ctx, fake_client, 'ATTACH')
        fake_client.get_diskRefs.assert_called_with(
            fake_client._app_vdc
        )
        # disk exist, can't attach
        disk_ref = self.generate_fake_client_disk_ref('some')
        fake_client.get_diskRefs = mock.MagicMock(return_value=[
            disk_ref
        ])
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run_volume_operation(fake_ctx, fake_client, 'ATTACH')
        fake_client._vapp.attach_disk_to_vm.assert_called_with(
            self.VAPPNAME, disk_ref
        )
        # disk exist, can't detach
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run_volume_operation(fake_ctx, fake_client, 'DETACH')
        fake_client._vapp.detach_disk_from_vm.assert_called_with(
            self.VAPPNAME, disk_ref
        )
        # wrong operation
        with self.assertRaises(cfy_exc.NonRecoverableError):
            _run_volume_operation(fake_ctx, fake_client, 'Wrong')
        # disk exist, can attach
        fake_client._vapp.attach_disk_to_vm = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        _run_volume_operation(fake_ctx, fake_client, 'ATTACH')
        # disk exist, can detach
        fake_client._vapp.detach_disk_from_vm = mock.MagicMock(
            return_value=self.generate_task(
                vcloud_plugin_common.TASK_STATUS_SUCCESS
            )
        )
        _run_volume_operation(fake_ctx, fake_client, 'DETACH')
        # disk exist, use internal resource
        fake_ctx._target.node.properties = {
            'volume': {
                'name': 'some'
            },
            'use_external_resource': False
        }
        _run_volume_operation(fake_ctx, fake_client, 'DETACH')
        fake_client._vapp.detach_disk_from_vm.assert_called_with(
            'some_other', disk_ref
        )
        # disk exist, use external resource
        fake_ctx._target.node.properties = {
            'volume': {
                'name': 'some'
            },
            'use_external_resource': False
        }
        fake_ctx._source.node.properties.update(
            {'use_external_resource': True})
        _run_volume_operation(fake_ctx, fake_client, 'DETACH')
        fake_client._vapp.detach_disk_from_vm.assert_called_with(
            'some_other', disk_ref
        )

    def _gen_volume_context_and_client(self):
        fake_client = self.generate_client()
        fake_ctx = self.generate_relation_context()
        fake_ctx._target.node.properties = {
            'use_external_resource': True
        }
        fake_ctx._source.node.properties = {
            'volume': {
                'name': 'some'
            },
            'vcloud_config': {
                'vdc': 'vdc_name',
            },
            'resource_id': 'some'
        }
        fake_ctx._target.instance.runtime_properties = {
            network_plugin.VCLOUD_VAPP_NAME: self.VAPPNAME
        }
        return fake_ctx, fake_client

    def test_attach_volume(self):
        """
            use external resource, try to attach but no disks
        """
        fake_ctx, fake_client = self._gen_volume_context_and_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.attach_volume(ctx=fake_ctx)

    def test_detach_volume(self):
        """
            use external resource, try to detach but no disks
        """
        fake_ctx, fake_client = self._gen_volume_context_and_client()
        with mock.patch(
            'vcloud_plugin_common.VcloudAirClient.get',
            mock.MagicMock(return_value=fake_client)
        ):
            volume.detach_volume(ctx=fake_ctx)

if __name__ == '__main__':
    unittest.main()
