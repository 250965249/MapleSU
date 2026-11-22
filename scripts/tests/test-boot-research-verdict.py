"""A successful harness process must not hide a failed image contract."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'boot_research_lifecycle', Path(__file__).with_name('test-ultra-boot-research-lifecycle.py'))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class VerdictTests(unittest.TestCase):
    def kernel_stages(self):
        return {'inspect': {'kernelSize': 4096}, **{
            name: {'passed': True} for name in (
                'prepareTarget', 'independentCompleteKernelReadback', 'sameGeneratorRepatchWithReceipt',
                'generatedKernelRecovery', 'repatchWithoutLocalReceipt', 'credentialChangeRepatch',
                'sourcePreservation')}}

    def test_process_success_does_not_hide_generation_failure(self):
        stages = self.kernel_stages()
        stages['prepareTarget'] = {'passed': False, 'code': 'PRO_KERNEL_GENERATE_TARGET_SYMBOL_MISSING'}
        result = lifecycle.assess_stages(stages)
        self.assertFalse(result['passed'])
        self.assertIn('prepareTarget', result['failedRequiredStages'])

    def test_kernel_success_requires_independent_readback_and_retry(self):
        stages = self.kernel_stages()
        self.assertTrue(lifecycle.assess_stages(stages)['passed'])
        del stages['independentCompleteKernelReadback']
        self.assertFalse(lifecycle.assess_stages(stages)['passed'])

    def test_init_boot_is_a_container_contract(self):
        stages = {'inspect': {'kernelSize': 0}, 'ramdiskContainerRoundtrip': {'passed': True},
                  'sourcePreservation': {'passed': True},
                  'ultraPrepareTarget': {'passed': False, 'code': 'PRO_KERNEL_BASE_NO_KERNEL'}}
        result = lifecycle.assess_stages(stages)
        self.assertTrue(result['passed'])
        self.assertEqual(result['scope'], 'ramdisk-container-only')

    def test_input_change_always_fails(self):
        stages = self.kernel_stages()
        stages['sourcePreservation']['passed'] = False
        self.assertFalse(lifecycle.assess_stages(stages)['passed'])

    def test_missing_inspection_is_not_an_init_boot(self):
        self.assertFalse(lifecycle.assess_stages({})['passed'])


if __name__ == '__main__':
    unittest.main()
