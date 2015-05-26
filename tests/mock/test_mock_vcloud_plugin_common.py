import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
import vcloud_plugin_common


class VcloudPluginCommonMockTestCase(test_mock_base.TestBase):
    """
        test for common vcloud logic
    """

    def test_get_mandatory(self):
        # wrong key
        with self.assertRaises(cfy_exc.NonRecoverableError):
            vcloud_plugin_common.get_mandatory(
                {'a': 'b'}, 'c'
            )

        # empty key
        with self.assertRaises(cfy_exc.NonRecoverableError):
            vcloud_plugin_common.get_mandatory(
                {'a': None}, 'a'
            )
        # everything fine
        self.assertEqual(
            vcloud_plugin_common.get_mandatory({
                'a': 'b'
            }, 'a'),
            'b'
        )

    def test_get_vcloud_config(self):
        # context.NODE_INSTANCE
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_ctx._instance = mock.Mock()
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            self.assertEqual(
                vcloud_plugin_common.get_vcloud_config(),
                {
                    'vdc': 'vdc_name'
                }
            )
        # context.RELATIONSHIP_INSTANCE
        fake_ctx = self.generate_relation_context()
        fake_ctx._source.node.properties = {
            'vcloud_config': {
                'vdc': 'vdc_name'
            }
        }
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            self.assertEqual(
                vcloud_plugin_common.get_vcloud_config(),
                {
                    'vdc': 'vdc_name'
                }
            )
        # context.DEPLOYMENT
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_ctx._source = None
        fake_ctx._instance = None
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            with self.assertRaises(cfy_exc.NonRecoverableError):
                vcloud_plugin_common.get_vcloud_config()

    def test_transform_resource_name(self):
        fake_ctx = self.generate_node_context()
        fake_ctx._bootstrap_context = mock.Mock()
        fake_ctx._bootstrap_context.resources_prefix = None
        # wrong resource name type
        with self.assertRaises(ValueError):
            vcloud_plugin_common.transform_resource_name(None, fake_ctx)
        with self.assertRaises(ValueError):
            vcloud_plugin_common.transform_resource_name(11, fake_ctx)
        # resource name string
        self.assertEqual(
            vcloud_plugin_common.transform_resource_name(
                'test', fake_ctx
            ),
            'test'
        )
        # resource name is dict
        self.assertEqual(
            vcloud_plugin_common.transform_resource_name(
                {'name': 'test'}, fake_ctx
            ),
            'test'
        )
        # prefix not exist in name
        fake_ctx._bootstrap_context.resources_prefix = 'prfx_'
        self.assertEqual(
            vcloud_plugin_common.transform_resource_name(
                'test', fake_ctx
            ),
            'prfx_test'
        )
        # prefix exist in name
        fake_ctx._bootstrap_context.resources_prefix = 'prfx_'
        self.assertEqual(
            vcloud_plugin_common.transform_resource_name(
                'prfx_test', fake_ctx
            ),
            'prfx_prfx_test'
        )

    def test_is_subscription(self):
        # subscription
        self.assertTrue(
            vcloud_plugin_common.is_subscription(
                vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            )
        )
        # ondemand
        self.assertFalse(
            vcloud_plugin_common.is_subscription(
                vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
            )
        )
        # None, by default used subscription service, so True
        self.assertTrue(
            vcloud_plugin_common.is_subscription(
                None
            )
        )

    def test_is_ondemand(self):
        # subscription
        self.assertFalse(
            vcloud_plugin_common.is_ondemand(
                vcloud_plugin_common.SUBSCRIPTION_SERVICE_TYPE
            )
        )
        # ondemand
        self.assertTrue(
            vcloud_plugin_common.is_ondemand(
                vcloud_plugin_common.ONDEMAND_SERVICE_TYPE
            )
        )
        # None, by default used subscription service, so False
        self.assertFalse(
            vcloud_plugin_common.is_ondemand(
                None
            )
        )

    def test_wait_for_task(self):
        fake_client = self.generate_client()
        # error in task
        fake_task = self.generate_task(
            vcloud_plugin_common.TASK_STATUS_ERROR
        )
        with self.assertRaises(cfy_exc.NonRecoverableError):
            vcloud_plugin_common.wait_for_task(fake_client, fake_task)
        # success in task
        fake_task = self.generate_task(
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        vcloud_plugin_common.wait_for_task(fake_client, fake_task)
        # success after wait
        fake_task = self.generate_task(
            None
        )
        fake_task_after_wait = self.generate_task(
            vcloud_plugin_common.TASK_STATUS_SUCCESS
        )
        sleep = mock.MagicMock(return_value=None)
        response = mock.Mock()
        response.content = 'Success'
        with mock.patch(
            'pyvcloud.schema.vcd.v1_5.schemas.vcloud.taskType.parseString',
            mock.MagicMock(return_value=fake_task_after_wait)
        ):
            with mock.patch(
                'requests.get', mock.MagicMock(return_value=response)
            ):
                with mock.patch(
                    'time.sleep',
                    sleep
                ):
                    vcloud_plugin_common.wait_for_task(
                        fake_client, fake_task
                    )

    def test_with_vca_client(self):
        # context.NODE_INSTANCE
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_client = self.generate_client()
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.VcloudAirClient.get',
                mock.MagicMock(return_value=fake_client)
            ):
                @vcloud_plugin_common.with_vca_client
                def _some_function(vca_client, **kwargs):
                    return vca_client

                self.assertEqual(
                    _some_function(ctx=fake_ctx),
                    fake_client
                )
        # context.DEPLOYMENT
        fake_ctx = self.generate_node_context(
            properties={
                'vcloud_config': {
                    'vdc': 'vdc_name'
                }
            }
        )
        fake_ctx._source = None
        fake_ctx._instance = None
        with mock.patch(
            'vcloud_plugin_common.ctx', fake_ctx
        ):
            with mock.patch(
                'vcloud_plugin_common.VcloudAirClient.get',
                mock.MagicMock(return_value=fake_client)
            ):
                @vcloud_plugin_common.with_vca_client
                def _some_function(vca_client, **kwargs):
                    return vca_client

                with self.assertRaises(cfy_exc.NonRecoverableError):
                    _some_function(ctx=fake_ctx),

    def test_config(self):
        # good case
        fake_file = mock.mock_open(read_data="test: test")
        with mock.patch(
            '__builtin__.open', fake_file
        ):
            config = vcloud_plugin_common.Config()
            self.assertEqual(
                config.get(),
                {'test': 'test'}
            )
        # bad case
        mock_for_raise = mock.MagicMock(side_effect=IOError('no file'))
        fake_file = mock.mock_open(mock_for_raise)
        with mock.patch(
            '__builtin__.open', fake_file
        ):
            config = vcloud_plugin_common.Config()
            self.assertEqual(
                config.get(),
                {}
            )

if __name__ == '__main__':
    unittest.main()
