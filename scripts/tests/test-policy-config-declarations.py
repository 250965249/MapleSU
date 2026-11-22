"""Reject executable/layout/conditional uses of a nominally harmless config."""
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from policy_config_declarations import declaration_configs

class DeclarationsTest(unittest.TestCase):
    def test_only_unreferenced_extern_array_is_accepted(self):
        key = 'CONFIG_VENDOR_ARRAY_BYTES'
        declaration = 'extern u64 vendor_pad[' + key + ' / sizeof(u64)];'
        classify = lambda source, imports=(): declaration_configs({'header.h': source}, {key: '2048'}, imports)
        self.assertEqual([key], classify(declaration))
        self.assertEqual([key], classify(declaration+'\nstatic inline void *f(void) { return &vendor_pad[0]; }'))
        for suffix in ('\nint f(void) { return sizeof(vendor_pad); }',
                       '\n#define FIELD_BYTES ' + key, '\n#if ' + key + '>1024\n#endif',
                       '\nvoid *f(void) { return vendor_pad; }'):
            self.assertEqual([], classify(declaration + suffix))
        self.assertEqual([], classify(declaration, ['vendor_pad']))
        self.assertEqual([], classify('struct task { u64 vendor_pad['+key+'/sizeof(u64)]; };'))
        self.assertEqual([], classify('u64 vendor_pad['+key+'/sizeof(u64)];'))
        self.assertEqual([key], classify('/* '+key+' */\n' + declaration))

if __name__ == '__main__': unittest.main()
