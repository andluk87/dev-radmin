import unittest
from analyze_etl import reassemble, split_frames


class ReassemblyTests(unittest.TestCase):
    def test_out_of_order_and_duplicate_segments(self):
        body, gap, conflicts = reassemble([(103, b'def'), (100, b'abc'), (100, b'abc')], 100)
        self.assertEqual((body, gap, conflicts), (b'abcdef', False, 0))

    def test_gap_is_not_concatenated_into_a_false_complete_frame(self):
        self.assertEqual(reassemble([(100, b'abc'), (104, b'ef')], 100), (b'abc', True, 0))

    def test_conflicting_overlap(self):
        body, gap, conflicts = reassemble([(100, b'abc'), (102, b'Zde')], 100)
        self.assertEqual((body, gap, conflicts), (b'abcde', False, 1))

    def test_sequence_wrap(self):
        self.assertEqual(reassemble([(0xfffffffe, b'ab'), (0, b'cd')], 0xfffffffe), (b'abcd', False, 0))

    def test_version_frame_and_partial_body(self):
        version = bytes.fromhex('0000000403000000')
        self.assertEqual(split_frames(version), ([4], 0, None))
        self.assertEqual(split_frames(version+b'\x00\x00\x00\x20abc'), ([4], 7, 'incomplete_frame'))

    def test_huge_frame_is_not_allocated(self):
        self.assertEqual(split_frames(bytes.fromhex('7fffffff')), ([], 4, 'advertised_length_exceeds_limit'))


if __name__ == '__main__':
    unittest.main()
