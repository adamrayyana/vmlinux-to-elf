from struct import pack_into
from unittest import TestCase

from vmlinux_to_elf.core.kallsyms import (
    KallsymsFinder,
    KallsymsNotFoundException,
)


class PcRelativeBaseTests(TestCase):
    def finder(self, image: bytes, base=None, is_64_bits=True):
        finder = object.__new__(KallsymsFinder)
        finder.kernel_img = image
        finder.explicit_base_address = base
        finder.is_64_bits = is_64_bits
        return finder

    def test_explicit_base_is_used_for_raw_image(self):
        base = 0xFFFFFFFFA1000000
        finder = self.finder(b'raw kernel memory', base)
        self.assertEqual(finder._pc_relative_base_address(8, '<'), base)

    def test_raw_image_without_base_has_actionable_error(self):
        finder = self.finder(b'raw kernel memory')
        with self.assertRaisesRegex(
            KallsymsNotFoundException, '--base-address'
        ):
            finder._pc_relative_base_address(8, '<')

    def test_elf_program_header_base_is_used(self):
        image = bytearray(0x80)
        image[:4] = b'\x7fELF'
        pack_into('<Q', image, 0x20, 0x40)
        pack_into('<Q', image, 0x50, 0xFFFFFFFF81000000)
        finder = self.finder(bytes(image))
        self.assertEqual(
            finder._pc_relative_base_address(8, '<'),
            0xFFFFFFFF81000000,
        )

    def test_invalid_elf_program_header_offset_is_rejected(self):
        image = bytearray(0x40)
        image[:4] = b'\x7fELF'
        pack_into('<Q', image, 0x20, 1 << 63)
        finder = self.finder(bytes(image))
        with self.assertRaisesRegex(
            KallsymsNotFoundException, 'program-header offset'
        ):
            finder._pc_relative_base_address(8, '<')
