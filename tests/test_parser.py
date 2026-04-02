import unittest
import os
import tempfile
from dir_parser import parse_log_file, _do_parse_log_file, LogFile


class TestParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, 'test.log')
        
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_do_parse_valid_file(self):
        with open(self.test_file, 'w') as f:
            f.write("2024-01-01 10:00:00 INFO test log\n")
            f.write("2024-01-01 10:01:00 ERROR failed login\n")
        
        result = _do_parse_log_file(self.test_file, None)
        
        self.assertIsInstance(result, LogFile)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.entries[0].level, 'INFO')
        self.assertEqual(result.entries[1].level, 'ERROR')
        self.assertEqual(result.errors, 0)
    
    def test_do_parse_with_max_lines(self):
        with open(self.test_file, 'w') as f:
            for i in range(10):
                f.write(f"line {i}\n")
        
        result = _do_parse_log_file(self.test_file, 5)
        
        self.assertEqual(len(result.entries), 5)
    
    def test_parse_file_not_found(self):
        result = parse_log_file(('/nonexistent/file.log', None, None))
        
        self.assertEqual(result.path, '/nonexistent/file.log')
        self.assertEqual(len(result.entries), 0)
        self.assertEqual(result.errors, 0)
    
    def test_parse_invalid_encoding(self):
        with open(self.test_file, 'wb') as f:
            f.write(b'\x80\x81\x82 invalid utf-8\n')
        
        result = parse_log_file((self.test_file, None, None))
        
        self.assertEqual(result.errors, 1)


if __name__ == '__main__':
    unittest.main()
