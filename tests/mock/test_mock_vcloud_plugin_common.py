import mock
import unittest

from cloudify import exceptions as cfy_exc
import test_mock_base
import vcloud_plugin_common


class VcloudPluginCommonMockTestCase(test_mock_base.TestBase):

    def test_get_mandatory(self):
        # wrong key
        with self.assertRaises(cfy_exc.NonRecoverableError):
            vcloud_plugin_common.get_mandatory(
                {'a': 'b'}, 'c'
            )

        #empty key
        with self.assertRaises(cfy_exc.NonRecoverableError):
            vcloud_plugin_common.get_mandatory(
                {'a': None}, 'a'
            )
        #everything fine
        self.assertEqual(
            vcloud_plugin_common.get_mandatory({
                'a': 'b'
            }, 'a'),
            'b'
        )

    def test_get_vcloud_config(self):
        # context.NODE_INSTANCE
        fake_ctx = self.generate_context(
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
        fake_ctx = self.generate_context(properties={})
        fake_ctx._source = mock.Mock()
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
        fake_ctx = self.generate_context(
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

if __name__ == '__main__':
    unittest.main()
